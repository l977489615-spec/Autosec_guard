"""
Adaptive Context Engine — AutoSec Guard
==========================================
针对 IVI 系统和静态 CAN 总线测试场景的多维自适应上下文引擎。

在静态测试场景下，物理车速监控意义不大；
真正有价值的自适应维度是：

1. 服务指纹自适应 (Service Fingerprint Adaptive Selection)
   发现目标开放的服务（SSH/HTTP/SOME-IP/UPnP）后，
   自动裁剪并排序 PoC 执行集合，只运行与当前目标服务匹配的模块。

2. 协议响应反馈闭环 (Protocol-Response Feedback Loop)
   每一步 PoC 的执行结果（NRC 响应码、Banner 信息、HTTP 头）
   都作为输入，动态调整下一步测试载荷和策略。

3. 认证状态感知 (Authentication State Awareness)
   自动检测目标是否启用认证机制（SSH 公钥/密码认证、HTTP Bearer、
   UDS Security Access 算法），并切换对应的漏洞验证路径。

4. 目标负载自适应 (IVI Load Adaptive Throttling)
   通过响应延迟探针动态感知 IVI 系统的资源负载，
   在目标设备过载（延迟 > 阈值）时自动降低发包频率，
   避免因测试导致 IVI 系统死机或假性漏报。

This is the Patent-1 Revised Core Implementation.
"""

import time
import socket
import logging
import threading
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# 认证机制类型定义
# ──────────────────────────────────────────────
class AuthType:
    NONE = "none"
    SSH_PASSWORD = "ssh_password"
    SSH_KEY_ONLY = "ssh_key_only"
    HTTP_BEARER = "http_bearer"
    HTTP_BASIC = "http_basic"
    UDS_DEFAULT_SESSION = "uds_default_session"
    UDS_SECURITY_ACCESS_27 = "uds_security_access_0x27"
    UNKNOWN = "unknown"


# ──────────────────────────────────────────────
# 协议响应反馈记录
# ──────────────────────────────────────────────
class ProtocolFeedback:
    """记录已执行 PoC 的响应反馈，供后续模块决策"""
    def __init__(self):
        self._history: List[dict] = []
        self._lock = threading.Lock()

    def record(self, poc_name: str, protocol: str, result: str,
               evidence: str = "", nrc_code: Optional[int] = None,
               latency_ms: float = 0.0):
        with self._lock:
            self._history.append({
                "poc": poc_name,
                "protocol": protocol,
                "result": result,       # "vulnerable" | "not_vulnerable" | "error" | "blocked"
                "evidence": evidence,
                "nrc_code": nrc_code,
                "latency_ms": latency_ms,
                "ts": time.time(),
            })
            logger.debug(f"[AdaptiveCtx] 反馈记录: {poc_name} → {result} "
                         f"(NRC=0x{nrc_code:02X} 延迟={latency_ms:.0f}ms)" if nrc_code else
                         f"[AdaptiveCtx] 反馈记录: {poc_name} → {result} (延迟={latency_ms:.0f}ms)")

    def get_nrc_for_protocol(self, protocol: str) -> List[int]:
        """获取某协议所有返回过的 NRC 码（用于判断安全等级）"""
        with self._lock:
            return [h["nrc_code"] for h in self._history
                    if h["protocol"] == protocol and h["nrc_code"] is not None]

    def has_vulnerability_in(self, protocol: str) -> bool:
        """检查某协议是否已确认漏洞（避免对同协议重复测试）"""
        with self._lock:
            return any(h["protocol"] == protocol and h["result"] == "vulnerable"
                       for h in self._history)

    def get_avg_latency(self) -> float:
        with self._lock:
            if not self._history:
                return 0.0
            return sum(h["latency_ms"] for h in self._history) / len(self._history)

    def to_list(self) -> List[dict]:
        with self._lock:
            return list(self._history)


# ──────────────────────────────────────────────
# IVI 目标负载探针
# ──────────────────────────────────────────────
class IVILoadProbe:
    """
    通过 TCP 握手延迟探针估算目标 IVI 系统当前负载状态。
    延迟 > HIGH_LATENCY_MS → 系统高负载，自动降低发包频率。
    """
    NORMAL_MS = 200
    HIGH_LATENCY_MS = 800
    CRITICAL_MS = 2000

    def __init__(self, target_ip: str, probe_port: int = 22):
        self.target_ip = target_ip
        self.probe_port = probe_port
        self._latencies: List[float] = []

    def probe(self) -> float:
        """发送单个 TCP 探针，返回连接延迟(ms)"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            t0 = time.time()
            s.connect((self.target_ip, self.probe_port))
            lat = (time.time() - t0) * 1000
            s.close()
            self._latencies.append(lat)
            return lat
        except socket.timeout:
            return self.CRITICAL_MS
        except Exception:
            return self.NORMAL_MS  # 连接被拒绝但很快，说明主机活跃

    def get_recommended_interval_ms(self) -> float:
        """
        根据平均延迟，推荐 PoC 执行间隔（毫秒）。
        延迟越高 → 间隔越长，保护 IVI 系统不被测试拖垮。
        """
        if not self._latencies:
            return 500  # 默认 0.5s 间隔
        avg = sum(self._latencies) / len(self._latencies)
        if avg < self.NORMAL_MS:
            return 300
        elif avg < self.HIGH_LATENCY_MS:
            return 800
        else:
            return 2000  # IVI 系统高负载，每 2s 一个 PoC

    def get_load_status(self) -> str:
        if not self._latencies:
            return "unknown"
        avg = sum(self._latencies) / len(self._latencies)
        if avg < self.NORMAL_MS:
            return "normal"
        elif avg < self.HIGH_LATENCY_MS:
            return "high"
        else:
            return "critical"


# ──────────────────────────────────────────────
# 认证状态感知探针
# ──────────────────────────────────────────────
class AuthStateDetector:
    """
    探测目标服务的认证状态，自动选择最优漏洞验证策略：
     - SSH 仅支持公钥 → 跳过密码爆破，尝试公钥伪造检测
     - HTTP 使用 Bearer Token → 分析 JWT 签名漏洞而非暴力破解
     - UDS SecurityAccess 已激活 → 先探测算法种子规律
    """

    def detect_ssh_auth(self, target_ip: str, port: int = 22) -> dict:
        """通过 SSH banner 和握手特征判断 SSH 认证模式"""
        result = {
            "service": "ssh",
            "port": port,
            "auth_type": AuthType.UNKNOWN,
            "banner": "",
            "recommended_strategy": "",
        }
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4.0)
            s.connect((target_ip, port))
            banner = s.recv(256).decode("utf-8", errors="ignore").strip()
            s.close()
            result["banner"] = banner

            # 尝试用 paramiko 探测支持的认证方式
            try:
                import paramiko
                transport = paramiko.Transport((target_ip, port))
                transport.connect()
                auth_methods = []
                try:
                    transport.auth_none("probe_user")
                except paramiko.ssh_exception.BadAuthenticationType as e:
                    auth_methods = getattr(e, "allowed_types", [])
                transport.close()

                if "password" in auth_methods:
                    result["auth_type"] = AuthType.SSH_PASSWORD
                    result["recommended_strategy"] = "credential_bruteforce"
                elif "publickey" in auth_methods and "password" not in auth_methods:
                    result["auth_type"] = AuthType.SSH_KEY_ONLY
                    result["recommended_strategy"] = "key_auth_bypass_check"
                else:
                    result["auth_type"] = AuthType.NONE
                    result["recommended_strategy"] = "direct_access"
            except Exception:
                result["auth_type"] = AuthType.SSH_PASSWORD  # 默认假设密码认证
                result["recommended_strategy"] = "credential_bruteforce"

        except Exception as e:
            result["banner"] = f"Error: {e}"
        return result

    def detect_http_auth(self, target_ip: str, port: int = 80, use_https: bool = False) -> dict:
        """通过 HTTP 响应头判断认证机制类型"""
        result = {
            "service": "http",
            "port": port,
            "auth_type": AuthType.UNKNOWN,
            "www_authenticate": "",
            "recommended_strategy": "",
        }
        try:
            proto = "https" if use_https else "http"
            import urllib.request
            req = urllib.request.Request(f"{proto}://{target_ip}:{port}/")
            req.add_header("User-Agent", "AutoSecGuard/1.0")
            try:
                urllib.request.urlopen(req, timeout=4)
                result["auth_type"] = AuthType.NONE
                result["recommended_strategy"] = "direct_exploit"
            except Exception as e:
                err_str = str(e)
                if "401" in err_str:
                    result["auth_type"] = AuthType.HTTP_BASIC
                    result["recommended_strategy"] = "credential_bruteforce"
                elif "403" in err_str:
                    result["auth_type"] = AuthType.HTTP_BEARER
                    result["recommended_strategy"] = "jwt_analysis"
                else:
                    result["auth_type"] = AuthType.NONE
                    result["recommended_strategy"] = "direct_exploit"
        except Exception as e:
            result["auth_type"] = AuthType.UNKNOWN
        return result

    def detect_uds_session_level(self, target_ip: str, port: int = 13400) -> dict:
        """
        通过 DoIP 发送 UDS TesterPresent / SecurityAccess 探针，
        判断 ECU 当前支持的会话级别和安全访问要求。
        """
        result = {
            "service": "uds",
            "auth_type": AuthType.UDS_DEFAULT_SESSION,
            "nrc_code": None,
            "recommended_strategy": "direct_uds_test",
        }
        # TesterPresent (0x3E, 0x00) → 若返回 0x7F 0x3E 0x7E = requestOutOfRange
        # 说明 SecurityAccess 已锁 → 需先刷种子
        TESTER_PRESENT = bytes([
            0x03, 0x3E, 0x00, 0x00,  # ISO-TP SF len=3, SID=TesterPresent
            0x00, 0x00, 0x00, 0x00,  # Padding
        ])
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((target_ip, port))
            s.sendall(TESTER_PRESENT)
            resp = s.recv(32)
            s.close()
            if len(resp) >= 3 and resp[1] == 0x7F:
                nrc = resp[2]
                result["nrc_code"] = nrc
                if nrc in (0x22, 0x33, 0x81):  # conditionsNotCorrect / securityAccess
                    result["auth_type"] = AuthType.UDS_SECURITY_ACCESS_27
                    result["recommended_strategy"] = "security_access_seed_analysis"
        except Exception:
            pass
        return result


# ──────────────────────────────────────────────
# 主自适应上下文引擎
# ──────────────────────────────────────────────

class AdaptiveContextEngine:
    """
    IVI 台架测试场景专用自适应上下文引擎。
    
    在每次扫描前，通过多维度上下文探测为后续 PoC 执行提供自适应决策支持：
      1. 基于服务指纹动态裁剪 PoC 执行集合
      2. 记录协议响应反馈，支持闭环策略调整
      3. 感知认证状态，自动切换最优攻击路径
      4. 监测 IVI 系统负载，动态调整扫描节奏
    """

    # 服务 → 相关 PoC 文件名关键词映射
    SERVICE_TO_POC_KEYWORDS: Dict[str, List[str]] = {
        "ssh": ["SSH", "ssh"],
        "http": ["HTTP", "http", "Web", "UPnP", "upnp"],
        "someip": ["SOMEIP", "someip", "SOME_IP"],
        "uds": ["UDS", "uds", "ECU", "ecu"],
        "can": ["CAN", "can"],
        "bluetooth": ["BLE", "ble", "Bluetooth", "bluetooth"],
        "telnet": ["Telnet", "telnet"],
        "upnp": ["UPnP", "upnp", "AVTransport"],
        "carplay": ["CarPlay", "carplay", "RTSP", "rtsp"],
        "adb": ["ADB", "adb", "Android"],
        "qnx": ["QNX", "qnx", "qconn"],
    }

    # 端口 → 服务类型映射
    PORT_TO_SERVICE: Dict[int, str] = {
        22: "ssh", 23: "telnet", 80: "http", 443: "http",
        8080: "http", 8443: "http", 1900: "upnp", 30490: "someip",
        13400: "uds", 6800: "http", 7000: "carplay", 5555: "adb",
        8000: "qnx",
    }

    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.feedback = ProtocolFeedback()
        self.load_probe = IVILoadProbe(target_ip)
        self.auth_detector = AuthStateDetector()
        self.detected_services: List[str] = []
        self.auth_contexts: List[dict] = []
        self._initialized = False

    def initialize(self, open_ports: List[int]) -> dict:
        """
        基于已知开放端口，执行快速多维上下文探测。
        返回完整的自适应上下文摘要，供 Agent 决策使用。
        """
        logger.info(f"[AdaptiveCtx] 开始上下文探测: {self.target_ip}, 开放端口={open_ports}")

        # Step 1: 识别活跃服务
        service_set = set()
        for port in open_ports:
            svc = self.PORT_TO_SERVICE.get(port)
            if svc:
                service_set.add(svc)
        self.detected_services = list(service_set)

        # Step 2: IVI 负载探测（选首个开放的 TCP 端口探针）
        probe_port = next((p for p in open_ports if p in (22, 80, 8080)), 80)
        self.load_probe.probe_port = probe_port
        latency = self.load_probe.probe()
        load_status = self.load_probe.get_load_status()
        recommended_interval = self.load_probe.get_recommended_interval_ms()

        # Step 3: 认证状态探测（并行探测主要服务）
        if "ssh" in self.detected_services and 22 in open_ports:
            auth_ctx = self.auth_detector.detect_ssh_auth(self.target_ip, 22)
            self.auth_contexts.append(auth_ctx)
            logger.info(f"[AdaptiveCtx] SSH 认证類型: {auth_ctx['auth_type']} → {auth_ctx['recommended_strategy']}")

        if "http" in self.detected_services:
            http_port = next((p for p in open_ports if p in (80, 8080)), 80)
            auth_ctx = self.auth_detector.detect_http_auth(self.target_ip, http_port)
            self.auth_contexts.append(auth_ctx)
            logger.info(f"[AdaptiveCtx] HTTP 认证类型: {auth_ctx['auth_type']} → {auth_ctx['recommended_strategy']}")

        if "uds" in self.detected_services and 13400 in open_ports:
            auth_ctx = self.auth_detector.detect_uds_session_level(self.target_ip, 13400)
            self.auth_contexts.append(auth_ctx)
            logger.info(f"[AdaptiveCtx] UDS 会话级别: {auth_ctx['auth_type']} → {auth_ctx['recommended_strategy']}")

        self._initialized = True
        context = self.get_context_summary(recommended_interval, load_status, latency)
        logger.info(f"[AdaptiveCtx] 上下文探测完成: 检测到服务={self.detected_services}, "
                    f"IVI负载={load_status}, 推荐执行间隔={recommended_interval}ms")
        return context

    def filter_pocs_by_service(self, all_pocs: List[str]) -> List[str]:
        """
        基于服务指纹上下文，从全量 PoC 列表中筛选与当前目标服务匹配的模块。
        无匹配服务信息时返回全部 PoC（兼容无初始化情况）。
        """
        if not self.detected_services or not self._initialized:
            return all_pocs

        matched_keywords = set()
        for svc in self.detected_services:
            keywords = self.SERVICE_TO_POC_KEYWORDS.get(svc, [])
            matched_keywords.update(keywords)

        filtered = [
            poc for poc in all_pocs
            if any(kw in poc for kw in matched_keywords)
        ]
        skipped = len(all_pocs) - len(filtered)
        logger.info(f"[AdaptiveCtx] 服务匹配过滤: {len(all_pocs)} → {len(filtered)} PoC "
                    f"(跳过 {skipped} 个不相关模块)")
        return filtered if filtered else all_pocs  # 若过滤结果为空，回退到全量

    def get_adaptive_strategy_for(self, protocol: str) -> str:
        """
        基于认证状态上下文和协议反馈历史，返回对指定协议的推荐测试策略。
        """
        # 优先使用认证探测结果
        for ctx in self.auth_contexts:
            if ctx.get("service") == protocol:
                return ctx.get("recommended_strategy", "default")

        # 次选：基于已有 NRC 反馈推断策略
        nrc_list = self.feedback.get_nrc_for_protocol(protocol)
        if 0x33 in nrc_list or 0x22 in nrc_list:
            return "security_access_seed_analysis"
        if 0x78 in nrc_list:
            return "response_pending_retry"

        return "default"

    def should_skip_poc(self, poc_name: str, protocol: str, is_disruptive: bool = False) -> Tuple[bool, str]:
        """
        基于反馈历史和安全策略判断是否应跳过某 PoC。
        """
        # 1. 如果同协议已确认漏洞，跳过冗余扫描 PoC
        if self.feedback.has_vulnerability_in(protocol):
            return True, f"同协议 {protocol} 已发现漏洞，跳过冗余扫描 PoC"

        # 2. 破坏性测试策略 (DoS)
        if is_disruptive:
            # 在没有显式授权的情况下，默认在自适应引擎中警告或跳过
            # 这里我们设定：如果系统当前处于高延迟状态，绝对禁止执行破坏性测试
            if self.load_probe.get_load_status() in ("high", "critical"):
                return True, f"目标系统当前负载过高 ({self.load_probe.get_load_status()})，严禁执行破坏性测试 (DoS)"
            
            # 返回 False 但在 logs 中记录警告（由 Orchestrator 决定是否继续）
            logger.warning(f"[Safety] 警告: PoC {poc_name} 具有破坏性 (DoS)，请确认环境允许。")
            
        return False, ""

    def get_throttle_delay(self) -> float:
        """返回当前建议的 PoC 执行间隔（秒），基于 IVI 负载状态"""
        return self.load_probe.get_recommended_interval_ms() / 1000.0

    def get_context_summary(self, recommended_interval: float = None,
                            load_status: str = None, latency: float = None) -> dict:
        """返回完整上下文摘要字典（供 API 和 Agent 使用）"""
        return {
            "target_ip": self.target_ip,
            "detected_services": self.detected_services,
            "auth_contexts": self.auth_contexts,
            "ivi_load": {
                "status": load_status or self.load_probe.get_load_status(),
                "latency_ms": latency or (self.load_probe._latencies[-1] if self.load_probe._latencies else 0),
                "recommended_interval_ms": recommended_interval or self.load_probe.get_recommended_interval_ms(),
            },
            "poc_filter_active": self._initialized and bool(self.detected_services),
            "protocol_feedback": self.feedback.to_list(),
            "strategies": {
                ctx.get("service"): ctx.get("recommended_strategy")
                for ctx in self.auth_contexts
            },
        }


# ──────────────────────────────────────────────
# 全局引擎实例管理
# ──────────────────────────────────────────────

_engines: Dict[str, AdaptiveContextEngine] = {}


def get_or_create_engine(target_ip: str) -> AdaptiveContextEngine:
    """每个目标 IP 单独维护一个上下文引擎实例（跨请求持久化反馈历史）"""
    if target_ip not in _engines:
        _engines[target_ip] = AdaptiveContextEngine(target_ip)
    return _engines[target_ip]


def clear_engine(target_ip: str):
    """重置指定目标的上下文（新轮次扫描时调用）"""
    if target_ip in _engines:
        del _engines[target_ip]

"""
Topology-Aware Network Scanner — AutoSec Guard
===============================================
发现车载以太网与 CAN 总线网络中的安全网关（SEC-GW）和域控制器（DCU），
自适应调整攻击向量策略：
  - 若目标 ECU 在网关后方 → 切换为多跳/横向移动利用链
  - 若无网关隔离 → 直接单播测试

This is the Patent-1 core: Topology-Aware Adaptive Routing.
"""

import socket
import struct
import time
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# 结果类
# ──────────────────────────────────────────────

class EcuNode:
    """代表网络中发现的一个 ECU 节点"""
    def __init__(self, ip: str = None, can_arb_id: int = None, name: str = "Unknown ECU"):
        self.ip = ip
        self.can_arb_id = can_arb_id
        self.name = name
        self.is_behind_gateway: bool = False
        self.gateway_hops: int = 0
        self.open_ports: List[int] = []
        self.uds_response_nrc: Optional[int] = None  # 最近收到的 NRC 响应码
        self.detected_os: Optional[str] = None
        self.services: List[dict] = []

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "can_arb_id": f"0x{self.can_arb_id:03X}" if self.can_arb_id else None,
            "name": self.name,
            "is_behind_gateway": self.is_behind_gateway,
            "gateway_hops": self.gateway_hops,
            "open_ports": self.open_ports,
            "uds_response_nrc": f"0x{self.uds_response_nrc:02X}" if self.uds_response_nrc else None,
            "detected_os": self.detected_os,
            "services": self.services,
        }


class TopologyMap:
    """当前扫描轮次的网络拓扑图"""
    def __init__(self):
        self.nodes: List[EcuNode] = []
        self.has_security_gateway: bool = False
        self.gateway_ip: Optional[str] = None
        self.recommended_attack_vector: str = "direct"  # 'direct' | 'lateral_wifi' | 'obd_tunnel'
        self.scan_timestamp: float = time.time()

    def add_node(self, node: EcuNode):
        self.nodes.append(node)

    def to_dict(self) -> dict:
        return {
            "has_security_gateway": self.has_security_gateway,
            "gateway_ip": self.gateway_ip,
            "recommended_attack_vector": self.recommended_attack_vector,
            "node_count": len(self.nodes),
            "nodes": [n.to_dict() for n in self.nodes],
            "scan_timestamp": self.scan_timestamp,
        }


# ──────────────────────────────────────────────
# 拓扑扫描器
# ──────────────────────────────────────────────

class TopologyAwareScanner:
    """
    车载以太网/CAN 拓扑感知扫描器
    
    检测流程：
    1. 端口探测：对目标 IP 的常见车载服务端口执行快速连接测试
    2. UDS 网关探测：发送携带无效凭证的诊断帧，通过 NRC 时序特征判断是否通过网关中继
    3. SOME/IP SD 枚举：广播 FindService 探测所有在线 ECU 服务
    4. 拓扑判决：综合分析结果，输出是否存在 SEC-GW 及推荐攻击向量
    """

    # 常见车载服务端口（ISO 13400 DoIP, SOME/IP, HTTP 诊断等）
    VEHICLE_PORTS = [
        (13400, "UDP", "DoIP Gateway"),
        (30490, "UDP", "SOME/IP SD"),
        (8080,  "TCP", "HTTP Diag"),
        (8443,  "TCP", "HTTPS Diag"),
        (22,    "TCP", "SSH"),
        (23,    "TCP", "Telnet"),
        (80,    "TCP", "HTTP"),
        (443,   "TCP", "HTTPS"),
        (6800,  "TCP", "Vehicle API"),
        (4500,  "UDP", "DoIP Entity"),
        (7000,  "TCP", "CarPlay RTSP"),
        (5555,  "TCP", "ADB Shell"),
        (8000,  "TCP", "QNX Qconn"),
        (1900,  "UDP", "UPnP SSDP"),
    ]

    # UDS 侦察探针：发送 DefaultSession 请求
    UDS_PROBE_PAYLOAD = bytes([0x02, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])  # ISO-TP SF

    def __init__(self, target_ip: str, timeout: float = 3.0, can_interface: str = "can0"):
        self.target_ip = target_ip
        self.timeout = timeout
        self.can_interface = can_interface
        self.topo_map = TopologyMap()

    def scan(self) -> TopologyMap:
        """执行完整拓扑扫描"""
        logger.info(f"[Topology] 开始对 {self.target_ip} 的拓扑感知扫描...")

        # Step 1: 端口发现
        self._scan_ports()

        # Step 2: DoIP 网关检测
        self._detect_doip_gateway()

        # Step 3: SOME/IP 服务枚举
        self._enumerate_someip_services()

        # Step 4: 根据综合分析推荐攻击向量
        self._determine_attack_vector()

        logger.info(
            f"[Topology] 扫描完成: SEC-GW={self.topo_map.has_security_gateway}, "
            f"推荐向量={self.topo_map.recommended_attack_vector}, "
            f"发现节点={len(self.topo_map.nodes)}"
        )
        return self.topo_map

    def _scan_ports(self):
        """快速多线程端口探测"""
        import concurrent.futures

        target_node = EcuNode(ip=self.target_ip, name="Primary Target")

        def probe_port(port, proto, service_name):
            try:
                if proto == "TCP":
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(self.timeout / 2)
                    result = s.connect_ex((self.target_ip, port))
                    s.close()
                    if result == 0:
                        return (port, service_name, True)
                elif proto == "UDP":
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(self.timeout / 2)
                    s.sendto(b"\x00", (self.target_ip, port))
                    try:
                        s.recvfrom(64)
                        s.close()
                        return (port, service_name, True)
                    except socket.timeout:
                        # UDP no response — port might still be open
                        pass
                    finally:
                        s.close()
            except Exception:
                pass
            return (port, service_name, False)

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            futures = {
                executor.submit(probe_port, port, proto, svc): (port, svc)
                for port, proto, svc in self.VEHICLE_PORTS
            }
            for future in concurrent.futures.as_completed(futures, timeout=self.timeout * 2):
                result = future.result()
                if result and result[2]:
                    port, svc_name, _ = result
                    target_node.open_ports.append(port)
                    target_node.services.append({"port": port, "service": svc_name})
                    logger.info(f"[Topology] 发现开放端口: {port} ({svc_name})")

        self.topo_map.add_node(target_node)

    def _detect_doip_gateway(self):
        """
        DoIP (ISO 13400-2) 网关探测
        发送 Vehicle Identity Request，解析响应识别 SEC-GW 的存在。
        同时测量响应延迟以推断转发跳数。
        """
        DOIP_VEHICLE_IDENTITY_REQ = bytes([
            0xFE, 0xFE,       # Sync byte
            0x00, 0x01,       # Protocol Version 
            0xFF, 0xFE,       # Inverse Protocol Version
            0x00, 0x01,       # Payload Type = Vehicle_Identity_Request
            0x00, 0x00, 0x00, 0x00  # Payload Length = 0
        ])

        direct_latencies = []
        gateway_latencies = []

        # 尝试直接 DoIP 连接
        for attempt in range(3):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                t_start = time.time()
                s.connect((self.target_ip, 13400))
                s.sendall(DOIP_VEHICLE_IDENTITY_REQ)
                resp = s.recv(256)
                latency = (time.time() - t_start) * 1000  # ms
                direct_latencies.append(latency)
                s.close()

                # 解析 DoIP 响应（Payload Type 0x0004 = VehicleAnnouncementMessage）
                if len(resp) >= 8:
                    payload_type = struct.unpack_from(">H", resp, 2)[0]
                    if payload_type in (0x0004, 0x0005):
                        logger.info(f"[Topology] DoIP 网关响应 (PT=0x{payload_type:04X}), 延迟={latency:.1f}ms")
                        self.topo_map.has_security_gateway = True
                        self.topo_map.gateway_ip = self.target_ip
            except Exception:
                pass

        # 延迟抖动分析：高抖动通常表明存在中间网关转发
        if len(direct_latencies) >= 2:
            latency_jitter = max(direct_latencies) - min(direct_latencies)
            if latency_jitter > 50:  # >50ms 抖动表明存在网关中继
                logger.info(f"[Topology] 延迟抖动 {latency_jitter:.1f}ms，推测存在中间网关")
                self.topo_map.has_security_gateway = True

    def _enumerate_someip_services(self):
        """SOME/IP SD 服务枚举（仅探测目标 IP，不扫描整个网段）"""
        SD_PORT = 30490

        # FindService wildcard
        find_msg = bytes([
            0xFF, 0xFF,  # Service ID
            0x81, 0x00,  # Method ID (SD)
            0x00, 0x00, 0x00, 0x1C,  # Length
            0xDE, 0xAD,  # Client ID
            0x00, 0x01,  # Session ID
            0x01, 0x01,  # Proto/Iface Ver
            0x00, 0x00,  # Msg Type + Return Code
            # SD Payload
            0xC0, 0x00, 0x00, 0x00,  # Flags + Reserved
            0x00, 0x00, 0x00, 0x10,  # Entries Array Length
            # FindService Entry (16 bytes)
            0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF,
            0x01, 0x00, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
            # Options Array Length
            0x00, 0x00, 0x00, 0x00,
        ])

        try:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            recv_sock.settimeout(2.0)
            try:
                recv_sock.bind(("0.0.0.0", 0))  # 使用随机端口，不抢占 30490
            except OSError:
                return

            # 只向目标 IP 发送单播 SOME/IP SD，不发广播
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            send_sock.sendto(find_msg, (self.target_ip, SD_PORT))
            send_sock.close()

            deadline = time.time() + 2.0
            while time.time() < deadline:
                try:
                    data, addr = recv_sock.recvfrom(4096)
                    # 严格限定：只接受来自目标 IP 的响应
                    if addr[0] == self.target_ip:
                        existing_ips = {n.ip for n in self.topo_map.nodes}
                        if addr[0] not in existing_ips:
                            node = EcuNode(ip=addr[0], name="SOME/IP Service")
                            node.services.append({"port": SD_PORT, "service": "SOME/IP SD"})
                            self.topo_map.add_node(node)
                        logger.info(f"[Topology] SOME/IP 响应来自目标: {addr[0]}")
                except socket.timeout:
                    break
            recv_sock.close()
        except Exception as e:
            logger.debug(f"[Topology] SOME/IP 枚举异常: {e}")


    def _determine_attack_vector(self):
        """
        综合拓扑分析结果，给出推荐攻击向量:
          - 'direct': 目标 ECU 直接可达，可直接单播 UDS/CAN
          - 'lateral_wifi': 存在 SEC-GW 隔离，建议尝试通过 IVI Wi-Fi 热点横向移动
          - 'obd_tunnel': 建议通过 OBD-II 物理接口 DoIP 隧道绕过网关
        """
        if not self.topo_map.has_security_gateway:
            self.topo_map.recommended_attack_vector = "direct"
            logger.info("[Topology] 无 SEC-GW 检测，推荐直接攻击向量")
            return

        # 检查是否存在 Wi-Fi/HTTP 服务（可能是 IVI AP 模式）
        node_ports = set()
        for node in self.topo_map.nodes:
            node_ports.update(node.open_ports)

        if any(p in node_ports for p in [80, 443, 8080]):
            self.topo_map.recommended_attack_vector = "lateral_wifi"
            logger.info("[Topology] 检测到 HTTP 服务 + SEC-GW，推荐横向 Wi-Fi 渗透路径")
        elif 13400 in node_ports:
            self.topo_map.recommended_attack_vector = "obd_tunnel"
            logger.info("[Topology] 检测到 DoIP 接口，推荐 OBD-II DoIP 隧道绕过路径")
        else:
            self.topo_map.recommended_attack_vector = "direct"
            logger.info("[Topology] SEC-GW 存在但无明确旁路，仍推荐直接测试")

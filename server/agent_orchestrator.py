"""
Multi-Agent Orchestrator — AutoSec Guard
==========================================
基于 OpenAI 兼容接口实现的多 Agent 协作自主渗透测试系统。

7 个专业 Agent 通过调用 MCP Server 工具协作完成完整的车辆渗透测试闭环：

  ┌─────────────────────────────────────────────────────┐
  │  Agent 1 (侦察 Recon)                                │
  │   → scan_ports, get_topology                        │
  │   → 输出: 发现的服务列表、拓扑图、建议攻击向量        │
  └──────────────────┬──────────────────────────────────┘
                     │ 侦察结果
  ┌──────────────────▼──────────────────────────────────┐
  │  Agent 2 (规划 Planner)                              │
  │   → 输出: 基于侦察结果的任务执行序列（无代码）        │
  └──────────────────┬──────────────────────────────────┘
                     │ 攻击计划纲要
  ┌──────────────────▼──────────────────────────────────┐
  │  Agent 3 (决策 Decision)                             │
  │   → list_pocs, check_safety                         │
  │   → 过滤可用资源，补充安全策略与参数                 │
  └──────────────────┬──────────────────────────────────┘
                     │ 有序攻击计划
  ┌──────────────────▼──────────────────────────────────┐
  │  Agent 4 (武器化 Weaponize) - 按需触发               │
  │   → 针对未知服务的协议感知型动态探测脚本生成         │
  └──────────────────┬──────────────────────────────────┘
                     │ Weaponized Payload
  ┌──────────────────▼──────────────────────────────────┐
  │  Agent 5 (执行 Executor)                             │
  │   → run_poc (沙箱隔离执行)                            │
  │   → 输出: 漏洞证据                                  │
  └──────────────────┬──────────────┬───────────────────┘
                     │ 漏洞证据      │ 连续失败
                     │              ▼
                     │ ┌───────────────────────────────┐
                     │ │ Agent 6 (反思 Reflector)      │
                     │ │ → 纠正执行计划，提供恢复建议  │
                     │ └────────────┬──────────────────┘
                     │              │ 调整后计划
  ┌──────────────────▼◄─────────────┘
  │  Agent 7 (评估 Assessment)                           │
  │   → 生成符合 ISO 21434 / UN R155 的安全报告          │
  │   → 输出: 最终安全评估报告 JSON + 建议               │
  └─────────────────────────────────────────────────────┘

使用方法:
  from agent_orchestrator import AgentOrchestrator
  orch = AgentOrchestrator(target_ip="192.168.100.1", llm_config={"api_key": "YOUR_KEY", "base_url": "https://..."})
  report = await orch.run_full_assessment()
"""

import os
import json
import time
import datetime
import logging
import asyncio
import traceback
import re
import uuid
import sys
import requests
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from config import get_config

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s')

CONFIG = get_config()
DYNAMIC_PROBE_TOKEN = "dynamic_unknown_service_probe"
DYNAMIC_PROBE_LEGACY_TOKENS = {"dynamic_0day"}
DYNAMIC_PROBE_FILENAME = "network/15_Dynamic_Unknown_Service_Probe.py"


def _is_dynamic_probe_name(poc_name: Any) -> bool:
    normalized = str(poc_name or "").strip()
    return normalized == DYNAMIC_PROBE_TOKEN or normalized in DYNAMIC_PROBE_LEGACY_TOKENS

# MCP Server 地址
MCP_SERVER = CONFIG.mcp_server

# ──────────────────────────────────────────────
# MCP Tool Caller — 供 Agent 调用
# ──────────────────────────────────────────────

# 主 AutoSec API 地址（供 run_poc / list_pocs 调用）
AUTOSEC_API = CONFIG.autosec_api

PHASE_SEQUENCE = ["recon", "planner", "decision", "weaponize", "execute", "reflector", "assess"]
PHASE_RETRY_LIMITS = {
    "recon": 2,
    "planner": 1,
    "decision": 2,
    "weaponize": 1,
    "execute": 2,
    "reflector": 1,
    "assess": 1,
}
SUPERVISOR_LIMITS = {
    "max_consecutive_same_tool_call": 2,
    "max_consecutive_stalled_result": 2,
    "max_cascading_errors": 3,
}
REFLECTOR_MAX_REENTRY = 2


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _utc_timestamp() -> str:
    return _utc_now().strftime('%Y-%m-%dT%H:%M:%SZ')


@dataclass
class AttackPlanItem:
    step: int
    poc_name: str
    parameters: Dict[str, Any]
    strategy: str = "default"
    reason: str = ""
    protocol: str = ""
    status: str = "pending"


@dataclass
class ExecutionResultItem:
    step: int
    poc_name: str
    status: str
    vulnerable: Optional[bool]
    evidence: str = ""
    error: str = ""
    strategy: str = "default"
    branch: str = "primary"
    requires_human_review: bool = False
    verification_status: str = ""
    manual_review: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """Unified evidence model. Each confirmed vulnerability becomes a Finding entity.
    Attack graph, physical impact, reports, and frontend all consume this structure.
    Logs are for tracing only, not as a source of truth."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    trace_id: str = ""
    poc_id: str = ""
    poc_name: str = ""
    target_ip: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    vulnerable: bool = True
    severity: str = "High"
    domain: str = "generic"
    evidence: str = ""
    error: str = ""
    source: str = "execution"
    detected_at: str = field(
        default_factory=_utc_timestamp
    )

    def to_legacy_dict(self) -> Dict[str, Any]:
        """Backward-compatible serialization for frontend/API consumers."""
        return {
            "id": self.id,
            "trace_id": self.trace_id,
            "pocId": self.poc_id or self.poc_name,
            "name": self.poc_name,
            "vulnerable": self.vulnerable,
            "severity": self.severity,
            "domain": self.domain,
            "description": self.evidence or f"Scan found {self.poc_name} risk on target.",
            "details": self.evidence or "",
            "error": self.error,
            "source": self.source,
            "target_ip": self.target_ip,
            "parameters": self.parameters,
            "detectedAt": self.detected_at,
        }


def _safe_json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def _sanitize_weaponized_code(raw_code: str) -> str:
    """Remove script entrypoints and dedent LLM output before re-indenting into exploit()."""
    lines = raw_code.splitlines()
    cleaned: list[str] = []
    skipping_main = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("if __name__") and "__main__" in stripped:
            skipping_main = True
            continue
        if skipping_main:
            if stripped and not line.startswith((" ", "\t")):
                skipping_main = False
            else:
                continue
        cleaned.append(line.rstrip())
    return "\n".join(cleaned).strip()


def _wrap_code_as_plugin(raw_code: str) -> str:
    """将 Weaponize Agent 生成的原始代码包装为合规的 IVIVulnerabilityPlugin 子类。

    sandbox_runner.py 要求模块中存在一个继承自 IVIVulnerabilityPlugin 的子类，
    并且该子类必须拥有 run_verify 方法。直接写入原始代码会导致
    'No valid plugin class found' 错误。
    """
    raw_code = _sanitize_weaponized_code(raw_code)
    # 如果生成的代码已经包含 IVIVulnerabilityPlugin 子类，直接返回
    if 'IVIVulnerabilityPlugin' in raw_code and 'class ' in raw_code:
        # 确保有 from iv_plugin_base import 语句
        if 'from iv_plugin_base import' not in raw_code and 'import iv_plugin_base' not in raw_code:
            raw_code = 'from iv_plugin_base import IVIVulnerabilityPlugin\n' + raw_code
        return raw_code

    # exploit() 内 try 块需要 12 空格缩进（class 4 + method 4 + try 4）
    indented_code = '\n'.join(
        ('            ' + line if line.strip() else '')
        for line in raw_code.splitlines()
    )

    return f'''"""
PoC Name: Dynamic Unknown Service Probe
Identifier: CWE-200
Component: Unknown Network Service
Category: Network
Severity: Medium
Description: Weaponize Agent 生成的协议感知型未知服务动态探测脚本
Prerequisites: 目标可达
"""
import sys
import socket
import time
from iv_plugin_base import IVIVulnerabilityPlugin


class DynamicUnknownServiceProbePlugin(IVIVulnerabilityPlugin):
    meta_poc_name = "Dynamic Unknown Service Probe"
    meta_cve_id = "CWE-200"
    meta_severity = "Medium"
    meta_protocol = "tcp"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Probe"

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def exploit(self):
        self.results["description"] = "未知服务动态指纹与异常响应探测"
        target_ip = self.target_ip
        target_port = self.target_port
        try:
{indented_code}
        except Exception as e:
            self.logger.error(f"动态未知服务探测脚本执行异常: {{e}}")
            self.results["vulnerable"] = False
            self.results["evidence"] = f"Exception: {{e}}"
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 {DYNAMIC_PROBE_FILENAME} <target_ip>")
        sys.exit(1)
    plugin = DynamicUnknownServiceProbePlugin({{"target_ip": sys.argv[1]}})
    plugin.run_verify()
'''


def _extract_json_payload(raw_text: Any) -> Tuple[Optional[Any], Optional[str]]:
    if isinstance(raw_text, (dict, list)):
        return raw_text, None

    if raw_text is None:
        return None, "empty response"

    text = str(raw_text).strip()
    if not text:
        return None, "empty response"

    candidates = [text]
    fence_match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    if fence_match:
        candidates.insert(0, fence_match.group(1).strip())

    start = min([idx for idx in (text.find("{"), text.find("[")) if idx != -1], default=-1)
    if start != -1:
        candidates.append(text[start:])

    last_error = None
    for candidate in candidates:
        try:
            return json.loads(candidate), None
        except Exception as exc:
            last_error = str(exc)

    return None, last_error or "invalid json"


def _normalize_plan_items(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, dict):
        # Look for common keys where LLMs wrap the plan list
        for key in ("attack_plan", "plan", "items", "steps", "tasks", "instructions"):
            value = payload.get(key)
            if isinstance(value, list) and len(value) > 0:
                payload = value
                break
        else:
            # If no obvious list found, maybe the dict itself is an item? 
            # Or if it's a dict like {"1": {...}, "2": {...}}, we should extract values
            if all(isinstance(k, str) and k.isdigit() for k in payload.keys()):
                # Handle numeric key mappings
                payload = [v for k, v in sorted(payload.items(), key=lambda x: int(x[0]))]

    if not isinstance(payload, list):
        return []

    normalized = []
    for index, item in enumerate(payload, start=1):
        if not isinstance(item, dict):
            continue
        poc_name = (
            item.get("poc_name")
            or item.get("filename")
            or item.get("poc")
            or item.get("name")
            or ""
        )
        if not poc_name:
            continue
        parameters = item.get("parameters") or item.get("params") or {}
        if not isinstance(parameters, dict):
            parameters = {}
        normalized.append(asdict(AttackPlanItem(
            step=index,
            poc_name=poc_name,
            parameters=parameters,
            strategy=item.get("strategy") or "default",
            reason=item.get("reason") or "",
            protocol=item.get("protocol") or "",
            status=item.get("status") or "pending",
        )))
    return normalized


def _normalize_execution_items(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, dict):
        for key in ("execution_results", "results", "items", "findings"):
            value = payload.get(key)
            if isinstance(value, list):
                payload = value
                break

    if not isinstance(payload, list):
        return []

    normalized = []
    for index, item in enumerate(payload, start=1):
        if not isinstance(item, dict):
            continue
        poc_name = (
            item.get("poc_name")
            or item.get("filename")
            or item.get("name")
            or item.get("pocId")
            or f"step_{index}"
        )
        normalized.append(asdict(ExecutionResultItem(
            step=item.get("step") or index,
            poc_name=poc_name,
            status=item.get("status") or ("vulnerable" if item.get("vulnerable") else "completed"),
            vulnerable=bool(item.get("vulnerable")),
            evidence=item.get("evidence") or item.get("details") or item.get("description") or "",
            error=item.get("error") or "",
            strategy=item.get("strategy") or "default",
            branch=item.get("branch") or "primary",
        )))
    return normalized


def _load_poc_catalog(tool_state: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    if tool_state is not None and tool_state.get("poc_catalog"):
        return tool_state["poc_catalog"]
    try:
        resp = requests.get(f"{AUTOSEC_API}/api/list_pocs", timeout=10)
        if resp.ok:
            pocs = resp.json().get("pocs", [])
            if tool_state is not None:
                tool_state["poc_catalog"] = pocs
            return pocs
    except Exception:
        pass
    return []


def _direct_tool_call(
    tool_name: str,
    params: dict,
    on_log: Optional[Callable[..., Any]] = None,
    tool_state: Optional[Dict[str, Any]] = None,
) -> dict:
    """
    直接本地调用扫描模块 — 不依赖 MCP Server 进程。
    当 MCP Server 未启动时自动降级到此路径。
    """
    try:
        if tool_name == "scan_ports":
            from topology_scanner import TopologyAwareScanner
            from agent_recon_bootstrap import parse_candidate_ports
            target_ip = str(params.get("target_ip") or "")
            if on_log:
                on_log({"type": "info", "message": f"[Topology] 开始对 {target_ip} 的端口扫描..."})
            timeout = float(params.get("timeout", 2.0))
            candidate_ports = parse_candidate_ports(
                params.get("candidate_ports") or (tool_state or {}).get("candidate_ports")
            )
            scanner = TopologyAwareScanner(target_ip, timeout=timeout, candidate_ports=candidate_ports)
            scanner._scan_ports()
            nodes = scanner.topo_map.nodes
            open_ports = nodes[0].open_ports if nodes else []
            services = getattr(nodes[0], "services", []) if nodes else []
            if on_log:
                on_log({"type": "success", "message": f"[Topology] 端口扫描完成，开放端口: {open_ports}"})
            return {"target_ip": target_ip, "open_ports": open_ports,
                    "services": services, "port_count": len(open_ports)}

        elif tool_name == "get_topology":
            from topology_scanner import TopologyAwareScanner
            target_ip = str(params.get("target_ip") or "")
            if on_log:
                on_log({"type": "info", "message": f"[Topology] 正在分析 {target_ip} 的网络拓扑结构..."})
            scanner = TopologyAwareScanner(target_ip, timeout=3.0)
            topo = scanner.scan()
            if on_log:
                on_log({"type": "info", "message": f"[Topology] 拓扑分析完成: SEC-GW={topo.has_security_gateway}, 推荐向量={topo.recommended_attack_vector}"})
            return topo.to_dict()

        elif tool_name == "get_adaptive_context":
            from physical_safety_monitor import get_or_create_engine
            target_ip = str(params.get("target_ip") or "")
            if on_log:
                 on_log({"type": "info", "message": f"[Safety] 获取自适应防护上下文: {target_ip}"})
            open_ports = params.get("open_ports") or []
            if isinstance(open_ports, str):
                open_ports = [int(p) for p in open_ports.split(",") if p.strip().isdigit()]
            engine = get_or_create_engine(target_ip)
            ctx = engine.initialize(open_ports)
            if on_log:
                 on_log({"type": "success", "message": f"[Safety] 自适应引擎初始化完成"})
            return ctx

        elif tool_name == "check_safety":
            from physical_safety_monitor import get_or_create_engine
            target_ip = params.get("target_ip", "")
            poc_name = params.get("poc_name", "")
            protocol = params.get("protocol", "")
            if on_log:
                on_log({"type": "info", "message": f"[Safety] 安全性检查: PoC={poc_name}, 协议={protocol}"})
            if not target_ip:
                return {"should_run": True, "strategy": "default", "reason": "No context"}
            engine = get_or_create_engine(target_ip)
            skip, reason = engine.should_skip_poc(poc_name, protocol)
            strategy = engine.get_adaptive_strategy_for(protocol) if protocol else "default"
            if on_log:
                status = "阻断" if skip else "允许"
                on_log({"type": "warning" if skip else "success", "message": f"[Safety] 检查结果: {status} 执行 ({reason or '通过'})"})
            return {
                "should_run": not skip,
                "strategy": strategy,
                "recommended_interval_s": engine.get_throttle_delay(),
                "reason": reason or "Context check passed",
            }

        elif tool_name == "list_pocs":
            if on_log:
                on_log({"type": "info", "message": f"[Scanner] 获取可用 PoC 库清单..."})
            # 调用本地 API 获取 PoC 列表（无需认证）
            pocs = _load_poc_catalog(tool_state)
            if pocs:
                poc_map = tool_state.setdefault("poc_filename_to_id", {}) if tool_state is not None else {}
                for p in pocs:
                    identifier = p.get("id") or p.get("filename")
                    filename = p.get("pocFile") or p.get("filename")
                    if filename and identifier:
                        poc_map[os.path.basename(filename)] = identifier
                        poc_map[filename] = identifier
                cat = params.get("category")
                if cat:
                    pocs = [p for p in pocs if cat.lower() in p.get("category_dir", "").lower()]
                if on_log:
                    on_log({"type": "success", "message": f"[Scanner] 已加载 {len(pocs)} 个漏洞探测模块"})
                return {"pocs": pocs, "count": len(pocs)}
            # 降级：直接扫描 PoC 目录
            import glob
            from poc_catalog import is_executable_poc_name
            pocs_dir = os.path.join(os.path.dirname(__file__), "pocs")
            files = glob.glob(os.path.join(pocs_dir, "**", "*.py"), recursive=True)
            pocs = [{"filename": os.path.relpath(f, pocs_dir),
                     "category_dir": os.path.basename(os.path.dirname(f))}
                    for f in files
                    if is_executable_poc_name(os.path.relpath(f, pocs_dir))]
            if on_log:
                on_log({"type": "info", "message": f"[Scanner] 本地加载 {len(pocs)} 个 PoC 脚本"})
            return {"pocs": pocs, "count": len(pocs)}

        elif tool_name == "run_poc":
            poc_name = params.get("poc_name") or params.get("poc_file") or params.get("filename")
            poc_params = params.get("params", {})
            autosec_api = str((tool_state or {}).get("autosec_api") or AUTOSEC_API).rstrip("/")
            try:
                resp = requests.post(
                    f"{autosec_api}/api/run_poc",
                    json={"filename": poc_name, "params": poc_params, "session_id": "agent_auto"},
                    timeout=90,
                )
                if resp.ok:
                    data = resp.json()
                    # 抓取 PoC 运行日志并回显
                    if on_log and "logs" in data:
                        if on_log:
                            on_log({"type": "info", "message": f"[Executor] 开始执行 PoC: {poc_name}"})
                        for log_entry in data["logs"]:
                            on_log(log_entry)
                        if on_log:
                            if data.get("requires_human_review") or data.get("verification_status") == "pending_manual_review":
                                status = "等待人工确认"
                            else:
                                status = "发现漏洞!" if data.get("vulnerable") else "未发现漏洞"
                            on_log({
                                "type": "warning" if data.get("requires_human_review") else ("success" if data.get("vulnerable") else "info"),
                                "message": f"[Executor] PoC 执行完毕: {status} (文件名: {poc_name})"
                            })
                    session_id = str((tool_state or {}).get("poc_session_id") or "agent_auto")
                    return {
                        "blocked": False,
                        "success": bool(data.get("success", True)),
                        "vulnerable": data.get("vulnerable") if data.get("vulnerable") is not None else None,
                        "evidence": data.get("evidence") or data.get("output", ""),
                        "logs": data.get("logs", []),
                        "trace_id": data.get("trace_id") or session_id,
                        "poc_id": data.get("poc_id") or poc_name,
                        "requires_human_review": bool(data.get("requires_human_review")),
                        "verification_status": data.get("verification_status", ""),
                        "manual_review": data.get("manual_review", {}),
                        "security_profile": data.get("security_profile", {}),
                    }
                return {"blocked": False, "error": f"{autosec_api} API {resp.status_code}: {resp.text[:200]}"}
            except Exception as e:
                return {"blocked": False, "error": f"{autosec_api}: {e}"}

        else:
            return {"error": f"Unknown tool: {tool_name}"}

    except Exception as e:
        logger.error(f"[DirectTool] {tool_name} 执行失败: {e}")
        return {"error": str(e)}


def call_mcp_tool(
    tool_name: str,
    params: dict,
    timeout: int = 90,
    on_log: Optional[Callable[..., Any]] = None,
    tool_state: Optional[Dict[str, Any]] = None,
) -> dict:
    """
    调用 MCP 工具。
    优先连接外部 MCP Server（端口 5003）；
    连接失败时自动降级为直接本地执行，无需单独启动 mcp_server.py。
    """
    if tool_name == "run_poc" and (tool_state or {}).get("prefer_direct_run_poc"):
        return _direct_tool_call(tool_name, params, on_log=on_log, tool_state=tool_state)

    try:
        resp = requests.post(
            f"{MCP_SERVER}/mcp/call",
            json={"tool": tool_name, "params": params},
            timeout=min(timeout, 5),  # MCP 连接探测用短超时
        )
        if resp.ok:
            result = resp.json().get("result", {})
            # 如果是运行 PoC，抓取日志
            if on_log and isinstance(result, dict) and "logs" in result:
                 for log in result["logs"]:
                     on_log(log)
            return result
    except requests.exceptions.ConnectionError:
        pass  # MCP Server 未运行，降级到直接调用
    except Exception:
        pass

    # 降级：直接本地执行
    logger.debug(f"[MCP→Direct] {tool_name} (MCP Server 不可达，使用本地执行)")
    return _direct_tool_call(tool_name, params, on_log=on_log, tool_state=tool_state)




# ──────────────────────────────────────────────
# Qwen / OpenAI-compatible LLM 调用包装
# ──────────────────────────────────────────────

class QwenAgent:
    """
    单个 Qwen Agent — 封装 LLM 调用，支持通过函数调用驱动 MCP 工具
    """
    def __init__(self, agent_name: str, system_prompt: str, mcp_tools: List[dict],
                 api_key: str,
                 base_url: str,
                 model_name: str = "qwen-plus", max_turns: int = 8, on_log: Optional[Callable[..., Any]] = None,
                 request_timeout_seconds: int = 120, connect_timeout_seconds: int = 15):
        self.agent_name = agent_name
        self.system_prompt = system_prompt
        self.mcp_tools = mcp_tools
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model_name = model_name
        self._max_turns = max_turns
        self._request_timeout_seconds = max(int(request_timeout_seconds or 120), 10)
        self._connect_timeout_seconds = max(int(connect_timeout_seconds or 15), 3)
        self.on_log = on_log
        self.tool_state: Dict[str, Any] = {}
        self.tool_history: List[Dict[str, Any]] = []
        self.supervisor_events: List[Dict[str, Any]] = []
        self.llm_usage: Dict[str, Any] = {}

    def _reset_usage(self):
        self.llm_usage = {
            "agent_name": self.agent_name,
            "model_name": self._model_name,
            "calls": 0,
            "tool_call_count": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "latency_ms_total": 0,
            "history": [],
        }

    def _record_usage(self, response: Dict[str, Any], latency_ms: int, tool_call_count: int = 0):
        usage = response.get("usage") or {}
        prompt_tokens = int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0)
        completion_tokens = int(usage.get("completion_tokens") or usage.get("output_tokens") or 0)
        total_tokens = int(usage.get("total_tokens") or (prompt_tokens + completion_tokens) or 0)
        self.llm_usage["calls"] += 1
        self.llm_usage["tool_call_count"] += int(tool_call_count or 0)
        self.llm_usage["prompt_tokens"] += prompt_tokens
        self.llm_usage["completion_tokens"] += completion_tokens
        self.llm_usage["total_tokens"] += total_tokens
        self.llm_usage["latency_ms_total"] += int(latency_ms or 0)
        self.llm_usage["history"].append({
            "timestamp": _utc_timestamp(),
            "latency_ms": int(latency_ms or 0),
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "tool_call_count": int(tool_call_count or 0),
        })

    def usage_summary(self) -> Dict[str, Any]:
        if not self.llm_usage:
            self._reset_usage()
        calls = max(int(self.llm_usage.get("calls") or 0), 1)
        return {
            **self.llm_usage,
            "avg_latency_ms": round(float(self.llm_usage.get("latency_ms_total") or 0) / calls, 2),
        }

    def _build_openai_tools(self) -> List[dict]:
        """将 MCP 工具格式转换为 OpenAI Function Calling 格式"""
        if not self.mcp_tools:
            return []
        tools = []
        for t in self.mcp_tools:
            tools.append({
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t.get("parameters", {"type": "object", "properties": {}})
                }
            })
        return tools

    def _record_supervisor_event(self, scope: str, message: str, severity: str = "warning"):
        event = {
            "scope": scope,
            "severity": severity,
            "message": message,
            "timestamp": _utc_timestamp(),
        }
        self.supervisor_events.append(event)
        if self.on_log:
            self.on_log({
                "type": "warning" if severity != "info" else "info",
                "message": f"[Supervisor:{self.agent_name}] {message}",
            })

    def _chat_completion(self, messages: List[dict], tools: Optional[List[dict]]) -> Dict[str, Any]:
        """Call an OpenAI-compatible chat completions endpoint without the SDK.

        The packaged edge workstation avoids bundling the OpenAI Python SDK
        because Nuitka compiles its transitive dependency graph very slowly on
        CI runners. The wire protocol used here is the same chat/completions
        JSON shape expected by Qwen and OpenAI-compatible gateways.
        """
        base_url = self._base_url.rstrip("/")
        endpoint = base_url if base_url.endswith("/chat/completions") else f"{base_url}/chat/completions"
        payload: Dict[str, Any] = {
            "model": self._model_name,
            "messages": messages,
        }
        if tools:
            payload["tools"] = tools

        response = requests.post(
            endpoint,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=(self._connect_timeout_seconds, self._request_timeout_seconds),
        )
        if response.status_code >= 400:
            raise RuntimeError(f"HTTP {response.status_code}: {response.text[:500]}")
        return response.json()

    def _tool_signature(self, tool_name: str, tool_params: Dict[str, Any]) -> str:
        return json.dumps({"tool": tool_name, "params": tool_params}, sort_keys=True, ensure_ascii=False)

    def _is_empty_tool_result(self, result: Dict[str, Any]) -> bool:
        if not isinstance(result, dict):
            return False
        if result.get("error") or result.get("blocked"):
            return False
        meaningful_keys = [key for key, value in result.items() if value not in ("", [], {}, None, False)]
        return len(meaningful_keys) == 0

    def _pre_tool_supervisor_guard(self, tool_name: str, tool_params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        signature = self._tool_signature(tool_name, tool_params)
        consecutive_same = 0
        for item in reversed(self.tool_history):
            if item.get("signature") == signature:
                consecutive_same += 1
            else:
                break
        if consecutive_same >= SUPERVISOR_LIMITS["max_consecutive_same_tool_call"]:
            message = (
                f"检测到连续重复调用同一工具 {tool_name}，已阻断本次调用。"
                "请调整参数、切换策略，或结束当前分支。"
            )
            self._record_supervisor_event("repeat_tool_call", message)
            return {
                "blocked": True,
                "supervisor_hint": message,
                "supervisor_action": "change_strategy",
            }
        return None

    def _post_tool_supervisor_guard(self, tool_name: str, tool_params: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(result, dict):
            return result

        signature = self._tool_signature(tool_name, tool_params)
        result_signature = json.dumps(result, sort_keys=True, ensure_ascii=False)
        is_error = bool(result.get("error"))
        is_empty = self._is_empty_tool_result(result)

        self.tool_history.append({
            "tool_name": tool_name,
            "signature": signature,
            "result_signature": result_signature,
            "is_error": is_error,
            "is_empty": is_empty,
        })

        consecutive_stalled = 0
        for item in reversed(self.tool_history):
            if item.get("tool_name") != tool_name:
                break
            if item.get("result_signature") != result_signature:
                break
            if item.get("is_error") or item.get("is_empty"):
                consecutive_stalled += 1
            else:
                break
        if consecutive_stalled >= SUPERVISOR_LIMITS["max_consecutive_stalled_result"]:
            message = (
                f"工具 {tool_name} 连续返回相同的空结果或错误，当前分支无进展。"
                "请切换参数、跳过该分支，或进入总结。"
            )
            self._record_supervisor_event("no_progress", message)
            result = {**result, "supervisor_hint": message, "supervisor_action": "change_strategy"}

        cascading_errors = 0
        for item in reversed(self.tool_history):
            if item.get("is_error"):
                cascading_errors += 1
            else:
                break
        if cascading_errors >= SUPERVISOR_LIMITS["max_cascading_errors"]:
            message = (
                "检测到连续工具错误，已触发错误扩散保护。"
                "请停止继续试探，汇总当前失败原因并结束该阶段。"
            )
            self._record_supervisor_event("cascading_errors", message, severity="error")
            result = {**result, "supervisor_hint": message, "supervisor_action": "stop_or_summarize"}

        return result

    def call(self, user_message: str, context: str = "") -> str:
        """
        向此 Agent 发送消息，LLM 可能触发工具调用，
        工具调用结果自动回传，直到 LLM 输出最终文本响应。
        """
        if not self._api_key:
            raise RuntimeError(
                f"[{self.agent_name}] API key 未配置。"
                "请在前端 Profile Settings 中填写当前用户的 AI 配置。"
            )
        if not self._base_url:
            raise RuntimeError(f"[{self.agent_name}] base_url 未配置。")

        full_prompt = f"上下文信息:\n{context}\n\n任务:\n{user_message}"

        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": full_prompt}
        ]
        self.tool_history = []
        self.supervisor_events = []
        self._reset_usage()

        openai_tools = self._build_openai_tools()

        # 多轮工具调用循环（含 429 指数退避重试）
        for turn in range(self._max_turns):
            # 429 重试逻辑：最多重试 3 次，指数退避
            last_err = None
            response = None
            for attempt in range(3):
                try:
                    start_llm = time.time()
                    response = self._chat_completion(messages, openai_tools)
                    llm_latency = int((time.time() - start_llm) * 1000)
                    usage = response.get("usage") or {}
                    token_count = usage.get("total_tokens", 0)
                    choices = response.get("choices") or []
                    tool_calls = []
                    if choices:
                        tool_calls = (choices[0].get("message") or {}).get("tool_calls") or []
                    self._record_usage(response, llm_latency, tool_call_count=len(tool_calls))
                    if self.on_log:
                        self.on_log({"type": "info", "message": f"[{self.agent_name}] LLM 调用完成 (延迟: {llm_latency}ms, 消耗Token: {token_count})"})
                    last_err = None
                    break
                except Exception as e:
                    err_str = str(e)
                    last_err = e
                    if "429" in err_str or "Too Many Requests" in err_str:
                        # 默认指数退避
                        wait = 10 * (attempt + 1)
                        logger.warning(f"[{self.agent_name}] 429 配额限制，等待 {wait}s 后重试 ({attempt+1}/3)…")
                        time.sleep(wait)
                    else:
                        # 非限速错误，不重试，直接返回错误摘要
                        full_err = traceback.format_exc()
                        logger.error(f"[{self.agent_name}] API 错误 ({type(e).__name__}): {err_str[:200]}\n{full_err}")
                        return f"[{self.agent_name}] API 错误: {err_str[:300]}"
            if last_err or not response:
                full_err = traceback.format_exc() if last_err else "No response"
                logger.error(f"[{self.agent_name}] 请求失败: {str(last_err)[:200]}\n{full_err}")
                return f"[{self.agent_name}] 请求失败或配额耗尽，请稍后重试。错误: {str(last_err)[:200]}"

            choices = response.get("choices") or []
            if not choices:
                return f"[{self.agent_name}] API 未返回 choices"

            message = choices[0].get("message") or {}

            # 如果没有工具调用，说明是最终文本响应
            tool_calls = message.get("tool_calls") or []
            if not tool_calls:
                return message.get("content") or "Agent 未返回有效响应"

            # 记录助理的工具调用请求
            messages.append(message)

            # 执行所有工具调用
            for tool_call in tool_calls:
                function_call = tool_call.get("function") or {}
                tool_name = function_call.get("name", "")
                try:
                    tool_params = json.loads(function_call.get("arguments") or "{}")
                except Exception:
                    tool_params = {}
                
                logger.info(f"[{self.agent_name}] → MCP Tool Call: {tool_name}({json.dumps(tool_params, ensure_ascii=False)[:80]})")
                if self.on_log:
                    self.on_log({"type": "info", "message": f"[{self.agent_name}] 调用工具: {tool_name}({json.dumps(tool_params, ensure_ascii=False)[:60]}...)"})

                tool_start_ts = time.time()
                result = self._pre_tool_supervisor_guard(tool_name, tool_params)
                if result is None:
                    result = call_mcp_tool(
                        tool_name,
                        tool_params,
                        on_log=self.on_log,
                        tool_state=self.tool_state,
                    )
                result = self._post_tool_supervisor_guard(tool_name, tool_params, result)
                
                tool_latency = int((time.time() - tool_start_ts) * 1000)
                tool_res_size = len(json.dumps(result, ensure_ascii=False))
                if self.on_log:
                    self.on_log({"type": "info", "message": f"[{self.agent_name}] 工具 {tool_name} 执行完毕 (延迟: {tool_latency}ms, 结果大小: {tool_res_size} bytes)"})
                
                # [修正] 确保无论是通过 MCP 还是直接调用，只要 run_poc 发现漏洞，就记入 findings
                if tool_name == "run_poc" and result.get("vulnerable"):
                    if self.on_log:
                        # [优化] 直接在消息中包含文件名，避免 Orchestrator 回溯查找失败
                        poc_filename = tool_params.get("poc_name") or tool_params.get("filename") or "unknown"
                        self.on_log({"type": "success", "message": f"[Executor] PoC 执行完毕: 发现漏洞! (文件名: {poc_filename})"})

                # 记录详细结果到日志
                if self.on_log:
                    res_summary = json.dumps(result, ensure_ascii=False)
                    if len(res_summary) > 150:
                        res_summary = res_summary[:150] + "..."
                    self.on_log({"type": "success", "message": f"[{self.agent_name}] 工具响应: {res_summary}"})

                logger.info(f"[{self.agent_name}] ← MCP Result: {json.dumps(result, ensure_ascii=False)[:120]}")

                # 将工具执行结果作为 tool 角色消息返回给大模型
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.get("id"),
                    "content": json.dumps(result, ensure_ascii=False)
                })

        return "Agent 达到最大工具调用轮次限制，停止"


# ──────────────────────────────────────────────
# 4 专业 Agent 定义
# ──────────────────────────────────────────────

RECON_AGENT_PROMPT = """
你是一名资深的智能网联汽车（ICV）网络侦察专家。
你的任务是对指定目标进行全面的网络侦察，包括：
1. 发现所有开放的网络端口和服务
2. 进行拓扑分析，确定是否存在安全网关（SEC-GW）
3. 调用 get_adaptive_context 获取服务指纹和认证机制
4. 评估最佳的攻击路径（direct / lateral_wifi / obd_tunnel）

使用提供给你的 MCP 工具执行侦察任务。完成后，以结构化 JSON 格式输出侦察摘要。
始终使用中文输出分析结论。
"""

DECISION_AGENT_PROMPT = """
你是一名经验丰富的汽车网络安全渗透专家，专注于 UDS、CAN、SOME/IP 等车载协议。
基于侦察 Agent 提供的目标信息和【可用资源】，你需要：
1. 阅读上下文中的【端口↔PoC 映射】与【PoC 元数据表】（已与 poc_coverage 对齐）；必要时再调用 list_pocs 核对。
   • poc_name 必须使用元数据表中 poc_file 列的完整路径（例如 network/03_SSH_Service.py）。
   • 【Global 扫描已检出】列表中的 PoC 应优先全部纳入攻击计划进行定向复验。
2. 调用 get_adaptive_context 获取目标的服务指纹和认证类型
3. 批准过滤如下 PoC（不得将其列入攻击计划）：
   • 如果【可用资源】中没有 bluetooth_mac，则跳过所有荷包名包含 "bluetooth"/"BT"/"ble" 的 PoC
   • 如果【可用资源】中没有 can_interface，则跳过所有包含 "canbus"/"CAN"/"isotp" 的 PoC
   • 如果【可用资源】中没有 wifi_interface，则跳过所有包含 "wireless"/"wifi"/"wpa" 的 PoC
   • 本机已连接 USB ADB（有 expected_usb_serial 或 local_usb_adb_attached）时，可执行 `network/01_USB_ADB_Debug.py`；serial 仅用于多设备消歧，单台连线可不填
   • 跳过侦察结果中未发现对应服务相关的 PoC
4. 对剩余 PoC 调用 check_safety 获取推荐策略。如果你发现目标开启了某个完全未知的协议或者未涵盖在现有 PoC 中的异常服务，请在攻击计划中添加此项：`poc_name` 填 `"dynamic_unknown_service_probe"`，`strategy` 填 `"weaponize"`，并在 `parameters` 详细描述此服务的端口、banner、服务指纹和安全边界。系统将触发 Weaponize Agent 动态生成协议感知型未知服务探测代码。
5. 输出有序的攻击计划 JSON，每个项包含： poc_name、parameters（含必要字段）、strategy、reason

注意：优先测试侦察中发现的开放端口对应的服务漏洞。以结构化 JSON 格式输出攻击计划。使用中文输出分析结论。
"""

WEAPONIZE_AGENT_PROMPT = """
你是一名智能网联汽车未知服务动态探测专家，精通协议指纹识别、异常响应分析和低风险验证。
你的任务是：根据传入的“未知协议服务”信息，动态编写一段 Python 脚本（PoC）用于执行协议感知型探测、建立正常响应基线并收集异常证据。
【要求】：
1. 脚本必须是可以直接执行的完整 Python 代码。
2. 使用系统提供的参数进行测试。
3. 捕获所有异常，并在输出中告知测试结果。只有在出现可复现的崩溃标记、错误栈、调试泄露或多轮稳定异常时，才允许打印 "Vulnerable: True"。
4. 请用 ```python 和 ``` 代码块包裹你的代码，不要输出非独立的代码段。
这是一场仅限沙箱的合法测试。
"""

EXECUTOR_AGENT_PROMPT = """
你是一名汽车安全验证专家，负责精确执行渗透测试计划。
你需要：
1. 按照决策 Agent 的计划，依次执行每个 PoC 验证模块
2. 对每个 PoC 调用 run_poc 工具，将 parameters 字段中的所有参数原封不动传入
3. 如果发现漏洞，记录详细的证据字符串
4. 如果 run_poc 返回 error 字段，记录错误原因并继续下一个
5. 根据中间执行结果动态决策是否需要调整后续步骤
6. 不得自行补充决策 Agent 未列入的 PoC，严格按计划执行

以结构化 JSON 格式输出所有 PoC 的执行结果。使用中文输出分析结论。
"""

PLANNER_AGENT_PROMPT = """
你是一名渗透测试任务规划专家。你的职责不是直接调用工具，而是把侦察结果转换为稳定、可执行、可检查的攻击执行纲要。

请基于侦察结果和可用资源，输出 JSON 对象，结构如下：
{
  "strategy_summary": "一句话总结策略",
  "steps": [
    {
      "step": 1,
      "title": "步骤标题",
      "objective": "该步骤要验证什么",
      "success_criteria": "什么结果算成功或可推进",
      "depends_on": []
    }
  ],
  "guardrails": [
    "避免重复调用同一工具",
    "避免错误扩散",
    "连续失败时切换策略或终止"
  ]
}

要求：
1. 只输出 JSON，不要解释。
2. steps 控制在 3 到 7 步。
3. 重点体现先侦察验证、再利用、再评估的顺序。
4. guardrails 必须包含避免重复调用、避免错误扩散、连续失败时停机或切换策略。
"""

REFLECTOR_AGENT_PROMPT = """
你是一名安全验证过程反思与优化专家（Reflector Agent）。
你需要基于侦察结果、任务编排、攻击计划、执行结果和监督事件，对本轮自动化渗透测试进行结构化复盘，并输出能够指导后续执行决策的审计意见。

请重点完成以下分析：
1. 判断各个步骤、各条攻击路径以及整体测试流程是否达到预期目标和 success criteria；
2. 判断当前结果属于哪一类：漏洞已得到有效验证、证据不足、执行失败、环境受限、前置条件不满足、目标已修复、路径不可达，或其他状态；
3. 分析执行过程中是否存在计划偏差、顺序不合理、步骤冗余、重复尝试、覆盖缺口、证据不足、风险控制问题或资源调度问题；
4. 当执行成功时，评估当前证据是否充分，是否应继续扩展验证、补充取证，或及时停止以避免无效或高风险动作；
5. 当执行失败、阻塞或结果异常时，诊断根本原因，并给出具体修正建议，例如参数修正、前置条件补足、替代路径、补充侦察、调整依赖关系、切换执行策略或直接终止路径；
6. 当某条攻击路径已经没有继续价值时，明确建议停止、剪枝、转向其他路径或转人工介入。

你的输出应当尽量清晰回答以下问题：
- 本轮执行是否有效；
- 哪些结果可信，哪些结果仍需补证；
- 哪些步骤需要调整；
- 下一步建议是什么（continue / retry / branch / stop / escalate）。

请严格输出一个 JSON 对象，不要输出 Markdown，不要输出代码块，也不要补充 JSON 之外的解释。输出字段如下：
{
  "summary": "对本轮执行的总体结论",
  "execution_effective": true,
  "evidence_sufficient": false,
  "outcome_status": "validated | evidence_insufficient | execution_failed | environment_limited | prerequisite_missing | target_hardened | path_unreachable | partial_success | other",
  "issues": [
    {
      "category": "coverage_gap | evidence_gap | plan_deviation | execution_failure | risk_control | resource_issue | other",
      "severity": "low | medium | high",
      "reason": "问题原因",
      "impact": "问题影响",
      "suggestion": "修正建议"
    }
  ],
  "next_action": "continue | retry | branch | stop | escalate",
  "next_phase": "recon | planner | decision | weaponize | execute | assess | none",
  "rerun_mode": "targeted | from_phase",
  "focus_steps": [1, 2],
  "focus_pocs": ["network/03_SSH_Service.py"],
  "reentry_required": false,
  "reason": "触发该下一步动作的直接原因"
}
"""

ASSESSMENT_AGENT_PROMPT = """
你是 AutoSec Guard 的首席车辆渗透测试报告工程师，具备资深红队、车联网安全扫描、IVI/T-Box/CAN/无线攻击面验证、ISO/SAE 21434 TARA、UN R155 CSMS 与工程整改闭环经验。
你的任务不是泛泛总结，而是把上下文中的侦察、计划、PoC 执行结果、漏洞发现和反思审计，整理成一份可交付给车厂安全团队、合规团队和研发修复团队的专业渗透测试/安全扫描报告。

━━ 第一性原理分析框架 ━━

在写报告前，必须在内部按以下逻辑完成判断，并把结论体现在正文中：
1. 资产是什么：识别本次证据实际触达的资产或域，例如 IVI、T-Box、网关、诊断域、CAN/UDS、蓝牙/Wi-Fi、USB、本地应用、日志/数据库/源码制品。上下文未提供时写“上下文未提供”。
2. 信任边界在哪里：判断攻击者需要处于远程网络、同网段、近场无线、USB/物理接触、本地调试、已获 shell、离线制品审计中的哪一种位置。
3. 安全属性受损是什么：按机密性、完整性、可用性、认证/授权、隔离边界、可追溯性、功能安全影响进行归类，不要只写“存在风险”。
4. 可利用链路是否闭合：入口条件、触发步骤、返回证据、获得能力、影响对象、业务/安全后果必须形成闭环；缺任一环节时降低证据可信度并标注待补证。
5. 证据等级是什么：高=自动化执行命中且有明确目标响应/文件/日志/状态变化；中=命中规则或环境迹象但缺少完整复现链；低=仅信息暴露、失败日志、人工待确认或静态弱信号。
6. 风险是否可复测：每个确认发现都要给出复测方法；不能复测的结论只能作为受限发现或后续建议。

━━ 最高优先级规则（必须严格遵守） ━━

1. 证据优先：报告中的每一个漏洞、风险等级、攻击路径和整改建议，必须能追溯到上下文中的【执行结果(JSON)】或【漏洞发现(JSON)】。不得编造未执行、未命中或无证据支撑的漏洞。
2. 区分事实与建议：已经验证的漏洞写为“确认发现”；未执行但建议后续覆盖的内容只能写入“后续测试建议”，并明确标注“未测试/不作为本次发现”。
3. 不夸大结论：失败、超时、前置条件缺失、环境不可达、人工确认缺失的结果，不得包装成漏洞；应归入“未确认/受限项”并说明限制原因。
4. 不使用空泛措辞：禁止用“存在大量安全隐患”“可能被攻击者利用”等无证据口号替代技术事实。每个高风险判断都要给出触发条件、攻击者位置、可利用证据和业务/安全影响。
5. 不泄露或扩写危险细节：可以描述验证方法和证据摘要，但不要提供可直接复用的攻击脚本、武器化 payload、默认口令清单或破坏性操作步骤。
6. 日期与团队强约束：报告评估日期必须使用上下文提供的【评估日期】或【当前时间】；评估团队必须写“BIOS团队”。
7. 语言与格式：使用中文、正式专业、Markdown 输出；不要输出 JSON，不要输出代码块包裹整份报告。

━━ 证据处理准则 ━━

- 优先使用【漏洞发现(JSON)】中 vulnerable=true 的 finding 作为确认漏洞清单；如没有漏洞发现，则从【执行结果(JSON)】中 vulnerable=true 的条目提取。
- 对每个确认漏洞必须引用：PoC/插件名称、目标、协议/攻击面（可从名称和参数推断，但必须标注为“基于 PoC 名称归类”）、执行状态、证据摘要、原始证据短摘录。
- 原始证据摘录要短而精准；如果证据很长，只摘取关键字段或关键行，不要整段复制日志。
- 对 vulnerable=false、completed、failed、timeout、manual_review_pending、environment_limited 等条目，要放在测试覆盖/未确认项中，不得写成漏洞。
- 静态制品类 PoC（Manifest、源码、SQLite、日志、APK/so 版本）必须明确写为“静态审计发现”，不得描述成已在目标运行时成功利用。
- 探测类 PoC（端口可达、协议握手、服务枚举）只能证明暴露面或前置条件，除非证据显示未授权访问、敏感信息泄露、状态改变或安全控制绕过，否则不得升级为漏洞。
- 高风险/破坏性 PoC 若被跳过、待审批或人工拒绝，必须写入“未验证高风险路径”，不得把跳过原因写成漏洞结论。
- 如果上下文包含反思审计，应把 evidence_sufficient、outcome_status、issues 和 next_action 融入“证据充分性与测试限制”。

━━ 风险评级方法 ━━

总体风险等级只能基于确认漏洞得出：
- CRITICAL：已验证可导致安全关键 ECU/诊断域/CAN 控制、远程代码执行、持久化控制、可跨域进入车控链路，或影响行车安全。
- HIGH：已验证可获得 IVI/T-Box/网关关键权限、绕过认证、敏感数据泄露后可横向移动，或可稳定造成高业务影响。
- MEDIUM：已验证暴露服务、弱配置、信息泄露、局部未授权访问，需额外条件才能升级影响。
- LOW：影响有限、利用条件较高、仅信息性或加固建议。
- NO CONFIRMED FINDING：所有执行项均未确认漏洞。

每个漏洞需给出：
- 风险等级：CRITICAL/HIGH/MEDIUM/LOW
- CVSS v3.1 参考向量和分值：若证据不足以精确评分，给“参考评分”并说明依据，不能伪装成正式 CVE 评分。
- ISO/SAE 21434 TARA：Threat Scenario、Attack Feasibility、Impact、Risk Value、Safety/Security Rationale。
- 影响链路：入口点 -> 漏洞/弱点 -> 获得能力 -> 影响对象 -> 业务/安全后果。
- 证据可信度：高/中/低，并说明“为什么足以确认”或“还缺什么证据”。

━━ 必须输出的报告结构 ━━

# 智能网联汽车安全评估报告

## 1. 报告元信息
使用表格列出：评估目标、目标 IP、评估日期、评估团队（BIOS团队）、报告类型、数据来源、确认漏洞数量、执行 PoC 数量。

## 2. 执行摘要
面向管理层，用 2-4 段说明本次真实验证范围、确认发现数量、最高风险等级、最关键影响、整改优先级。若无确认漏洞，明确写“本次自动化验证未确认可利用漏洞”，并说明仍受测试范围限制。

## 3. 关键发现总览
用 Markdown 表格列出确认漏洞：编号、漏洞/PoC 名称、攻击面、目标/端口/参数、风险等级、证据状态、主要影响、整改优先级。
如果没有确认漏洞，写“无确认漏洞”，不要强行生成表格内容。

## 4. 测试范围与执行覆盖
列出实际执行的 PoC/插件、状态、是否发现漏洞、证据摘要。明确区分：
- 已确认漏洞
- 未发现漏洞的测试项
- 执行失败/环境受限/证据不足项
- 未执行/被审批阻断的高风险项

## 5. 漏洞详细分析
对每个确认漏洞分别写一个小节，结构必须包含：
- 漏洞概述：一句话说明本次确认了什么，而不是介绍通用漏洞背景。
- 受影响对象：目标、端口/协议/组件/ECU 或系统域；未知字段写“上下文未提供”。
- 验证证据：PoC 名称、执行状态、关键参数、证据短摘录、证据可信度（高/中/低）及原因。
- 攻击路径：入口点 -> 利用条件 -> 获得能力 -> 影响对象 -> 可能后果。
- 风险评级：CVSS v3.1 参考向量/分值、ISO/SAE 21434 TARA 表格、评级依据。
- 影响分析：技术影响、业务影响、车端安全影响、是否跨越信任边界；没有证据支撑的影响要写“未在本次验证中确认”。
- 修复建议：立即处置、短期加固、长期治理、回归验证方法、验收标准。

## 6. 证据充分性与测试限制
说明哪些结论证据充分，哪些受限于网络可达性、目标状态、权限、人工确认、安全策略、PoC 覆盖范围。不得把限制项写成漏洞。

## 7. 合规性与工程治理评估
围绕 UN R155 CSMS 和 ISO/SAE 21434 给出与本次证据相关的差距，不要泛泛罗列法规。至少覆盖：资产/攻击面管理、漏洞验证与分级、日志与证据保全、修复闭环、回归验证。

## 8. 整改路线图
按优先级输出表格：优先级、整改动作、适用漏洞/资产、责任团队建议、预期风险降低、回归验证方法。只针对确认漏洞和明确暴露的弱点给整改动作。

## 9. 复测与验收标准
给出可执行的复测清单：复测 PoC、期望安全结果、需要采集的证据、通过/失败判据。没有确认漏洞时，也要给出下一轮覆盖建议的验收标准。

## 10. 后续测试建议
列出本次未覆盖或证据不足但值得后续验证的方向，并逐项标注“未测试/待补证”，例如固件、USB、本地物理访问、蓝牙、Wi-Fi、CAN/UDS、OTA、云端接口等。仅在上下文显示相关攻击面或测试限制时提出。

## 11. 结论
用专业、克制的语言给出最终风险判断、处置优先级和复测建议。

━━ 写作质量要求 ━━

- 结论必须具体到资产、攻击面、PoC 和证据，不写模板化套话。
- 表格内容要简洁但信息密度高；正文解释风险因果链。
- 对车联网场景要体现工程语境：IVI、T-Box、网关、诊断域、CAN/UDS、无线入口、媒体服务、云控链路、功能安全影响。
- 当输入信息不足时，写“上下文未提供”，不要自行补全车型、ECU、端口、CVE、供应商或法规结论。
- 输出只能是最终报告正文。
"""


def build_assessment_call(
    target_ip: str,
    target_name: str = "Unknown Target",
    context: str = "",
    report_date: Optional[str] = None,
) -> Dict[str, str]:
    """Shared report metadata builder for global scans and agent scans."""
    effective_report_date = report_date or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    effective_target_name = target_name or target_ip or "Unknown Target"

    prompt = (
        f"基于对智能网联汽车目标 '{effective_target_name}' ({target_ip}) 的完整渗透测试结果，"
        "生成证据驱动、可审计、可整改闭环的专业安全评估报告。"
        f"【当前时间】{effective_report_date}。"
        f"报告中的评估日期必须写 {effective_report_date}，评估团队必须写 BIOS团队。"
        "请严格以执行结果和漏洞发现为依据，不得把未测试项或失败项写成确认漏洞。"
    )

    context_prefix = (
        f"【当前时间】{effective_report_date}\n"
        f"【评估日期】{effective_report_date}\n"
        f"【评估团队】BIOS团队\n"
        f"【评估目标】{effective_target_name}\n"
        f"【目标IP】{target_ip}\n\n"
    )

    return {
        "prompt": prompt,
        "context": f"{context_prefix}{context or ''}",
    }


def create_assessment_agent(
    llm_config: Optional[Dict[str, Any]] = None,
    on_log: Optional[Callable[..., Any]] = None,
) -> QwenAgent:
    llm_config = llm_config or {}
    api_key = str(llm_config.get("api_key") or "").strip()
    base_url = str(llm_config.get("base_url") or "").strip()
    fast_model = str(llm_config.get("fast_model") or "qwen-plus").strip()
    strong_model = str(llm_config.get("strong_model") or fast_model or "qwen-max").strip()
    report_model = str(llm_config.get("report_model") or strong_model or fast_model or "qwen-max").strip()
    request_timeout_seconds = int(llm_config.get("llm_timeout_seconds") or 120)
    connect_timeout_seconds = int(llm_config.get("llm_connect_timeout_seconds") or 15)

    return QwenAgent(
        "评估Agent",
        ASSESSMENT_AGENT_PROMPT,
        [],
        api_key=api_key,
        base_url=base_url,
        model_name=report_model,
        on_log=on_log,
        request_timeout_seconds=request_timeout_seconds,
        connect_timeout_seconds=connect_timeout_seconds,
    )


def generate_assessment_report(
    *,
    target_ip: str,
    target_name: str = "Unknown Target",
    llm_config: Optional[Dict[str, Any]] = None,
    context: str = "",
    report_date: Optional[str] = None,
    on_log: Optional[Callable[..., Any]] = None,
) -> str:
    assessment_input = build_assessment_call(
        target_ip=target_ip,
        target_name=target_name,
        context=context,
        report_date=report_date,
    )
    return create_assessment_agent(llm_config=llm_config, on_log=on_log).call(
        assessment_input["prompt"],
        context=assessment_input["context"],
    )

# ──────────────────────────────────────────────
# 主协作编排器
# ──────────────────────────────────────────────

class AgentOrchestrator:
    """
    多 Agent 协作自主渗透测试编排器
    
    调度 4+ 个专业 Agent 完成从侦察到报告的完整渗透测试闭环。
    """

    def __init__(self, target_ip: str, target_name: str = "Vehicle Target",
                 llm_config: Optional[Dict[str, Any]] = None,
                 auth_token: Optional[str] = None,
                 can_interface: str = "",
                 bluetooth_mac: str = "",
                 wifi_interface: str = "",
                 rf_frequency: str = "",
                 expected_usb_serial: str = "",
                 usb_mount_point: str = "",
                 candidate_ports: str = "",
                 global_recon_seed: Optional[Dict[str, Any]] = None,
                 baseline_replay_pocs: Optional[List[str]] = None,
                 use_enhanced_recon: bool = True,
                 skip_assessment_report: bool = False,
                 autosec_api: str = "",
                 interactive_review: Optional[bool] = None,
                 poc_coverage_path: str = ""):
        self.trace_id = str(uuid.uuid4())
        self.target_ip = target_ip
        self.target_name = target_name
        self.start_time = time.time()
        self.candidate_ports = str(candidate_ports or "").strip()
        self.global_recon_seed = global_recon_seed if isinstance(global_recon_seed, dict) else None
        self.baseline_replay_pocs = [
            str(item).strip()
            for item in (baseline_replay_pocs or [])
            if str(item).strip()
        ]
        self.use_enhanced_recon = bool(use_enhanced_recon)
        self.skip_assessment_report = bool(skip_assessment_report)
        self.autosec_api = str(autosec_api or AUTOSEC_API).rstrip("/")
        self.interactive_review = sys.stdin.isatty() if interactive_review is None else bool(interactive_review)
        self.manual_review_wait_seconds = 0.0
        self.poc_coverage_path = str(poc_coverage_path or "").strip()

        # 可用资源上下文（Agent 决策过滤依据）
        self.available_params: Dict[str, str] = {"target_ip": target_ip}
        if self.candidate_ports:
            self.available_params["candidate_ports"] = self.candidate_ports
        if can_interface:
            self.available_params["can_interface"] = can_interface
        if bluetooth_mac:
            self.available_params["bluetooth_mac"] = bluetooth_mac
        if wifi_interface:
            self.available_params["wifi_interface"] = wifi_interface
        if rf_frequency:
            self.available_params["frequency"] = rf_frequency
        from adb_usb_utils import (
            list_local_usb_adb_serials,
            local_usb_adb_attached,
            resolve_usb_adb_serial,
            usb_adb_block_reason,
        )

        explicit_usb = str(expected_usb_serial or "").strip()
        attached_serials = list_local_usb_adb_serials()
        if explicit_usb:
            if explicit_usb in attached_serials:
                self.available_params["expected_usb_serial"] = explicit_usb
                self.available_params["usb_device_serial"] = explicit_usb
            else:
                self.available_params["usb_adb_block_reason"] = (
                    f"未在 adb devices 中找到 serial={explicit_usb}。"
                )
        elif local_usb_adb_attached():
            resolved_usb_serial = resolve_usb_adb_serial("", auto_single=True)
            self.available_params["local_usb_adb_attached"] = "true"
            self.available_params["expected_usb_serial"] = resolved_usb_serial
            self.available_params["usb_device_serial"] = resolved_usb_serial
        else:
            block_reason = usb_adb_block_reason()
            if block_reason:
                self.available_params["usb_adb_block_reason"] = block_reason
        if usb_mount_point:
            self.available_params["usb_mount_point"] = usb_mount_point

        llm_config = llm_config or {}
        self.llm_api_key = str(llm_config.get("api_key") or "").strip()
        self.llm_base_url = str(llm_config.get("base_url") or "").strip()
        self.fast_model = str(llm_config.get("fast_model") or "qwen-plus").strip()
        self.strong_model = str(llm_config.get("strong_model") or self.fast_model or "qwen-max").strip()
        self.report_model = str(llm_config.get("report_model") or self.strong_model or self.fast_model or "qwen-max").strip()
        self.llm_timeout_seconds = max(int(llm_config.get("llm_timeout_seconds") or 120), 10)
        self.llm_connect_timeout_seconds = max(int(llm_config.get("llm_connect_timeout_seconds") or 15), 3)
        logger.info(
            "[Orchestrator] LLM profile selected: fast_model=%s strong_model=%s report_model=%s timeout=%ss",
            self.fast_model,
            self.strong_model,
            self.report_model,
            self.llm_timeout_seconds,
        )

        # 从 MCP Server 获取工具描述
        self.mcp_tools = self._load_mcp_tools()

        # 运行日志缓冲区
        self.current_logs: List[dict] = []
        self.phase_records: List[dict] = []
        self.execution_trace: List[dict] = []

        # 初始化 Agent
        core_model = str(llm_config.get("core_model") or self.fast_model).strip()
        self.recon_agent = QwenAgent("侦察Agent", RECON_AGENT_PROMPT, self.mcp_tools, api_key=self.llm_api_key, base_url=self.llm_base_url, model_name=core_model, on_log=self._add_log, request_timeout_seconds=self.llm_timeout_seconds, connect_timeout_seconds=self.llm_connect_timeout_seconds)
        self.planner_agent = QwenAgent("规划Agent", PLANNER_AGENT_PROMPT, [], api_key=self.llm_api_key, base_url=self.llm_base_url, model_name=core_model, on_log=self._add_log, request_timeout_seconds=self.llm_timeout_seconds, connect_timeout_seconds=self.llm_connect_timeout_seconds)
        self.decision_agent = QwenAgent("决策Agent", DECISION_AGENT_PROMPT, self.mcp_tools, api_key=self.llm_api_key, base_url=self.llm_base_url, model_name=core_model, on_log=self._add_log, request_timeout_seconds=self.llm_timeout_seconds, connect_timeout_seconds=self.llm_connect_timeout_seconds)
        self.weaponize_agent = QwenAgent("Weaponize Agent", WEAPONIZE_AGENT_PROMPT, [], api_key=self.llm_api_key, base_url=self.llm_base_url, model_name=self.strong_model, on_log=self._add_log, request_timeout_seconds=self.llm_timeout_seconds, connect_timeout_seconds=self.llm_connect_timeout_seconds)
        self.executor_agent = QwenAgent("执行Agent", EXECUTOR_AGENT_PROMPT, self.mcp_tools,
                                           api_key=self.llm_api_key, base_url=self.llm_base_url, model_name=core_model, max_turns=20, on_log=self._add_log, request_timeout_seconds=self.llm_timeout_seconds, connect_timeout_seconds=self.llm_connect_timeout_seconds)
        self.assessment_agent = create_assessment_agent(
            llm_config={
                "api_key": self.llm_api_key,
                "base_url": self.llm_base_url,
                "fast_model": self.fast_model,
                "strong_model": self.strong_model,
                "report_model": self.report_model,
                "llm_timeout_seconds": self.llm_timeout_seconds,
                "llm_connect_timeout_seconds": self.llm_connect_timeout_seconds,
            },
            on_log=self._add_log,
        )
        self.reflector_agent = QwenAgent("反思Agent", REFLECTOR_AGENT_PROMPT, [], api_key=self.llm_api_key, base_url=self.llm_base_url, model_name=core_model, on_log=self._add_log, request_timeout_seconds=self.llm_timeout_seconds, connect_timeout_seconds=self.llm_connect_timeout_seconds)
        self.core_model = core_model

        # 结果存储
        self.recon_result: Optional[str] = None
        self.attack_plan: Optional[str] = None
        self.execution_results: Optional[str] = None
        self.final_report: Optional[str] = None
        self.structured_results: Dict[str, Any] = {
            "recon": {},
            "planner": {},
            "attack_plan": {"items": []},
            "execution": {"items": []},
            "reflector": {},
            "assessment": {},
            "supervisor": {"events": [], "metrics": {}, "adjustments": []},
            "llm_usage": {"per_agent": {}, "totals": {}},
        }

        # 发现的漏洞清单 (Structured Findings)
        self.findings: List[dict] = []
        # PoC 文件名到 ID 的映射，用于完善 findings
        self.poc_filename_to_id = {}
        self._finding_names = set()
        self.reflector_reentry_count = 0
        self.reflector_reentry_history: List[Dict[str, Any]] = []

        tool_state = {
            "poc_filename_to_id": self.poc_filename_to_id,
            "auth_token": auth_token,
            "candidate_ports": self.candidate_ports,
            "autosec_api": self.autosec_api,
            "prefer_direct_run_poc": True,
            "poc_session_id": "agent_auto",
        }
        self.recon_agent.tool_state = tool_state
        self.decision_agent.tool_state = tool_state
        self.executor_agent.tool_state = tool_state

    def _console(self, message: str) -> None:
        print(message, flush=True)

    def _load_poc_meta(self, poc_name: str) -> Dict[str, Any]:
        if not self.poc_coverage_path:
            return {}
        try:
            with open(self.poc_coverage_path, "r", encoding="utf-8") as fh:
                coverage = json.load(fh)
        except Exception:
            return {}
        normalized = str(poc_name or "").replace("\\", "/")
        base = os.path.basename(normalized)
        for item in coverage.get("pocs", []) or []:
            item_file = str(item.get("poc_file") or "").replace("\\", "/")
            if item_file == normalized or os.path.basename(item_file) == base:
                return item
        return {}

    def _resolve_poc_profile(self, poc_ref: str) -> Dict[str, Any]:
        """按 display_id / poc_name / 文件名 解析重入目标 PoC 的安全元数据。"""
        if not self.poc_coverage_path:
            return {}
        try:
            with open(self.poc_coverage_path, "r", encoding="utf-8") as fh:
                coverage = json.load(fh)
        except Exception:
            return {}
        ref = str(poc_ref or "").strip()
        ref_base = os.path.basename(ref.replace("\\", "/"))
        for item in coverage.get("pocs", []) or []:
            if ref and ref in (
                str(item.get("display_id") or ""),
                str(item.get("poc_name") or ""),
                str(item.get("poc_file") or ""),
                os.path.basename(str(item.get("poc_file") or "").replace("\\", "/")),
            ):
                return item
            if ref_base and ref_base == os.path.basename(str(item.get("poc_file") or "").replace("\\", "/")):
                return item
        # 兜底：仅返回引用名，让下游按非破坏性处理
        return {"display_id": ref, "poc_name": ref}

    def _plan_reentry_safety(self, reflector: Dict[str, Any]) -> List[Dict[str, Any]]:
        """重入风险再判定 + 安全补证策略：对反思指定的重入目标 PoC 逐个生成
        原样重跑/低扰动等效探针/只读降级/一次性授权/阻断策略。"""
        try:
            import reentry_safety
        except Exception:
            return []
        focus_pocs = reflector.get("focus_pocs") or []
        if not focus_pocs:
            return []
        issues_text = " ".join(
            str((i or {}).get("reason") or "") for i in (reflector.get("issues") or [])
        )
        recon = self.structured_results.get("recon", {}) or {}
        target_state = str((recon.get("adaptive_context") or {}).get("load_status") or "")
        ctx = {
            "target": getattr(self, "target_ip", "") or "",
            "failure_reason": issues_text,
            "evidence_gap": reflector.get("outcome_status") or "",
            "target_state": target_state,
            "retry_count": int(getattr(self, "reflector_reentry_count", 0) or 0),
            "param_changed": bool(reflector.get("focus_steps")),
        }
        profiles = [self._resolve_poc_profile(ref) for ref in focus_pocs]
        plans = reentry_safety.plan_safe_reentry_batch(profiles, ctx)
        reflector["safe_revalidation"] = plans
        return plans

    def _is_high_risk_poc(self, poc_name: str) -> Tuple[bool, Dict[str, Any]]:
        meta = self._load_poc_meta(poc_name)
        level = str(meta.get("destructive_level") or "").strip().lower()
        high_risk = bool(meta.get("high_risk") or meta.get("is_disruptive")) or level in {"restart", "dataloss", "brick"}
        return high_risk, meta

    def _prompt_high_risk_approval(self, poc_name: str, meta: Dict[str, Any], params: Dict[str, Any]) -> Tuple[bool, float]:
        if not self.interactive_review:
            return False, 0.0
        started = time.time()
        self._console("\n" + "=" * 72)
        self._console(f"[HIGH-RISK POC] {poc_name}")
        self._console(f"PoC: {meta.get('poc_name') or poc_name}")
        self._console(f"Severity: {meta.get('severity') or 'UNKNOWN'}")
        self._console(f"Destructive Level: {meta.get('destructive_level') or 'UNKNOWN'}")
        self._console(f"Protocol: {meta.get('protocol') or 'UNKNOWN'}")
        self._console(f"Params: {json.dumps(params, ensure_ascii=False)}")
        self._console("该 PoC 被标记为高风险/破坏性操作。输入 y 执行，输入 n 跳过。")
        while True:
            choice = input("执行该高风险 PoC? [y/n]: ").strip().lower()
            if choice in {"y", "yes"}:
                return True, round(time.time() - started, 3)
            if choice in {"n", "no", ""}:
                return False, round(time.time() - started, 3)
            self._console("请输入 y 或 n。")

    def _prompt_manual_verdict(self, poc_name: str, result: Dict[str, Any]) -> Tuple[Dict[str, Any], float]:
        if not self.interactive_review:
            result["manual_review_wait_seconds"] = 0.0
            return result, 0.0
        manual_review = result.get("manual_review") or {}
        started = time.time()
        self._console("\n" + "=" * 72)
        self._console(f"[MANUAL REVIEW] {poc_name}")
        self._console(str(manual_review.get("prompt") or "该 PoC 已执行完成，请人工观察目标侧效果后给出结论。"))
        observations = manual_review.get("required_observations") or []
        if observations:
            self._console("需要观察：")
            for index, observation in enumerate(observations, start=1):
                self._console(f"  {index}. {observation}")
        self._console("可选结论：1=confirmed_vulnerable, 2=confirmed_not_vulnerable, 3=inconclusive, 4=needs_retest")
        mapping = {
            "1": "confirmed_vulnerable",
            "2": "confirmed_not_vulnerable",
            "3": "inconclusive",
            "4": "needs_retest",
            "confirmed_vulnerable": "confirmed_vulnerable",
            "confirmed_not_vulnerable": "confirmed_not_vulnerable",
            "inconclusive": "inconclusive",
            "needs_retest": "needs_retest",
        }
        verdict = mapping.get(input("请输入结论编号或名称（回车保持 pending）: ").strip())
        if not verdict:
            wait_seconds = round(time.time() - started, 3)
            result["manual_review_wait_seconds"] = wait_seconds
            return result, wait_seconds
        operator_note = input("观察备注（可留空）: ").strip()
        evidence_file = input("证据文件路径（可留空）: ").strip()
        wait_seconds = round(time.time() - started, 3)
        result["manual_review_wait_seconds"] = wait_seconds
        try:
            response = requests.post(
                f"{self.autosec_api}/api/poc_manual_verdict",
                json={
                    "trace_id": result.get("trace_id") or self.trace_id,
                    "session_id": result.get("trace_id") or self.trace_id,
                    "poc_id": result.get("poc_id") or poc_name,
                    "poc_name": poc_name,
                    "target_ip": self.target_ip,
                    "target_mac": self.available_params.get("target_mac") or self.available_params.get("bluetooth_mac") or "",
                    "verdict": verdict,
                    "operator_note": operator_note,
                    "evidence_file": evidence_file,
                },
                timeout=120,
            )
            if response.ok:
                payload = response.json()
                result["vulnerable"] = payload.get("vulnerable")
                result["verification_status"] = payload.get("verification_status")
                result["manual_review"] = payload.get("manual_review", result.get("manual_review"))
                if operator_note:
                    result["evidence"] = operator_note
            else:
                result["error"] = f"manual verdict submit failed: HTTP {response.status_code}: {response.text[:200]}"
        except Exception as exc:
            result["error"] = f"manual verdict submit failed: {exc}"
        return result, wait_seconds

    def _bootstrap_recon(self) -> Dict[str, Any]:
        """增强侦察：candidate_ports 全口扫描 + 可选 Global scan_results 种子。"""
        from agent_recon_bootstrap import (
            enhanced_port_scan,
            merge_recon_results,
            parse_candidate_ports,
        )

        chunks: list[Dict[str, Any]] = []
        if self.global_recon_seed:
            chunks.append(self.global_recon_seed)
        if self.use_enhanced_recon:
            ports = parse_candidate_ports(self.candidate_ports)
            chunks.append(enhanced_port_scan(self.target_ip, ports))
        merged = merge_recon_results(*chunks) if chunks else {}
        if merged.get("open_ports"):
            try:
                ctx = _direct_tool_call(
                    "get_adaptive_context",
                    {"target_ip": self.target_ip, "open_ports": merged["open_ports"]},
                    on_log=self._add_log,
                )
                merged["adaptive_context"] = ctx
            except Exception as exc:
                logger.warning("[Orchestrator] bootstrap adaptive_context failed: %s", exc)
        return merged

    def _apply_heuristic_attack_plan_if_empty(self, recon_data: Dict[str, Any]) -> None:
        plan = self.structured_results.get("attack_plan") or {}
        if plan.get("items"):
            return
        from agent_recon_bootstrap import build_heuristic_attack_plan

        open_ports = recon_data.get("open_ports") or []
        if not open_ports:
            return
        heuristic = build_heuristic_attack_plan(
            open_ports,
            self.available_params,
            recon_data.get("global_vulnerable_pocs"),
        )
        if not heuristic.get("items"):
            return
        self.structured_results["attack_plan"] = heuristic
        self.attack_plan = _safe_json_dumps(heuristic)
        self._record_supervisor_event(
            "heuristic_attack_plan",
            f"决策 Agent 未产出有效计划，已启用规则回退（{heuristic.get('item_count', 0)} 步）。",
            phase="decision",
        )

    def _sort_attack_plan_recon_first(self) -> None:
        plan = self.structured_results.setdefault("attack_plan", {"items": []})
        items = [item for item in (plan.get("items") or []) if isinstance(item, dict)]
        if not items:
            return
        indexed = list(enumerate(items))
        indexed.sort(
            key=lambda pair: (
                0 if str(pair[1].get("poc_name") or "").replace("\\", "/").startswith("reconnaissance/") else 1,
                pair[0],
            )
        )
        reordered = []
        for step, (_, item) in enumerate(indexed, start=1):
            copied = dict(item)
            copied["step"] = step
            reordered.append(copied)
        if reordered == items:
            return
        plan["items"] = reordered
        plan["item_count"] = len(reordered)
        self.structured_results["attack_plan"] = plan
        self.attack_plan = _safe_json_dumps(plan)
        self._record_supervisor_event(
            "reconnaissance_first_order",
            "已将 reconnaissance 类 PoC 调整到 Agent 执行队列最前。",
            severity="info",
            phase="decision",
        )

    def _append_baseline_replay_plan_items(self) -> None:
        """实验复验模式：补跑 Global 已检出的漏洞 PoC，避免模型少量择优导致召回失真。"""
        if not self.baseline_replay_pocs:
            return
        plan = self.structured_results.setdefault("attack_plan", {"items": []})
        items = list(plan.get("items") or [])
        existing = {str(item.get("poc_name") or "").strip() for item in items if isinstance(item, dict)}

        try:
            from poc_catalog import is_executable_poc_name
        except Exception:
            is_executable_poc_name = lambda name: True  # type: ignore[assignment]

        next_step = max([int(item.get("step") or 0) for item in items if isinstance(item, dict)] + [0]) + 1
        added = 0
        skipped: list[str] = []
        for poc_name in self.baseline_replay_pocs:
            if poc_name in existing:
                continue
            if not is_executable_poc_name(poc_name):
                skipped.append(poc_name)
                continue
            items.append({
                "step": next_step,
                "poc_name": poc_name,
                "parameters": self._default_execution_params(),
                "strategy": "baseline_replay",
                "reason": "实验复验：Global 扫描已检出该 PoC 为阳性，追加执行以计算客观召回。",
            })
            existing.add(poc_name)
            next_step += 1
            added += 1

        if not added and not skipped:
            return
        plan["items"] = items
        plan["item_count"] = len(items)
        self.structured_results["attack_plan"] = plan
        self.attack_plan = _safe_json_dumps(plan)
        if added:
            self._record_supervisor_event(
                "baseline_replay_append",
                f"已追加 {added} 个 Global 阳性 PoC 进入 baseline replay 复验队列。",
                phase="decision",
            )
        if skipped:
            self._record_supervisor_event(
                "baseline_replay_skip_invalid",
                f"baseline replay 中 {len(skipped)} 个 PoC 不在可执行目录，已跳过: {skipped}",
                phase="decision",
            )

    def _refresh_llm_usage(self):
        agents = [
            self.recon_agent,
            self.planner_agent,
            self.decision_agent,
            self.weaponize_agent,
            self.executor_agent,
            self.reflector_agent,
            self.assessment_agent,
        ]
        per_agent = {}
        per_model: Dict[str, Dict[str, Any]] = {}
        totals: Dict[str, Any] = {
            "calls": 0,
            "tool_call_count": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "latency_ms_total": 0,
        }
        for agent in agents:
            summary = agent.usage_summary()
            per_agent[agent.agent_name] = summary
            model_name = str(summary.get("model_name") or "unknown")
            model_bucket = per_model.setdefault(model_name, {
                "model_name": model_name,
                "calls": 0,
                "tool_call_count": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "latency_ms_total": 0,
            })
            for key in totals.keys():
                totals[key] += int(summary.get(key) or 0)
                model_bucket[key] += int(summary.get(key) or 0)
        totals["avg_latency_ms"] = round(totals["latency_ms_total"] / max(totals["calls"], 1), 2)
        for bucket in per_model.values():
            bucket["avg_latency_ms"] = round(bucket["latency_ms_total"] / max(bucket["calls"], 1), 2)
        self.structured_results["llm_usage"] = {
            "per_agent": per_agent,
            "per_model": per_model,
            "totals": totals,
        }

    def _upsert_phase_record(
        self,
        phase: str,
        status: str,
        attempt: int = 0,
        raw_output: Any = "",
        structured_output: Any = None,
        error: str = "",
    ) -> dict:
        existing = next((r for r in self.phase_records if r["phase"] == phase), None)
        if existing is None:
            existing = {
                "phase": phase,
                "status": status,
                "attempt": attempt,
                "timestamp": _utc_timestamp(),
                "raw_output": "",
                "structured_output": {},
                "error": "",
                "history": [],
            }
            self.phase_records.append(existing)

        existing.update({
            "status": status,
            "attempt": max(existing.get("attempt", 0), attempt),
            "timestamp": _utc_timestamp(),
            "raw_output": raw_output if isinstance(raw_output, str) else _safe_json_dumps(raw_output),
            "structured_output": structured_output or {},
            "error": error,
        })
        existing["history"].append({
            "status": status,
            "attempt": attempt,
            "timestamp": existing["timestamp"],
            "error": error,
        })
        return existing

    def _record_phase(self, phase: str, status: str, raw_output: Any, structured_output: Any = None, error: str = ""):
        self._upsert_phase_record(
            phase=phase,
            status=status,
            raw_output=raw_output,
            structured_output=structured_output,
            error=error,
        )

    def _register_finding(
        self,
        poc_name: str,
        evidence: str = "",
        severity: str = "High",
        error: str = "",
        source: str = "execution",
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Optional[dict]:
        if not poc_name or poc_name in self._finding_names:
            return None

        poc_id = self.poc_filename_to_id.get(poc_name) or self.poc_filename_to_id.get(os.path.basename(poc_name))

        # 自动推断 domain（复用 assessment_engine 的分类规则）
        domain = "generic"
        try:
            from assessment_engine import classify_finding
            domain = classify_finding({"name": poc_name}).get("domain", "generic")
        except Exception:
            pass

        finding_obj = Finding(
            trace_id=self.trace_id,
            poc_id=poc_id or poc_name,
            poc_name=poc_name,
            target_ip=self.target_ip,
            parameters=parameters or {},
            severity=severity,
            domain=domain,
            evidence=evidence,
            error=error,
            source=source,
        )
        finding_dict = finding_obj.to_legacy_dict()
        self.findings.append(finding_dict)
        self._finding_names.add(poc_name)
        return finding_dict

    def _normalize_recon_result(self, raw_text: str) -> Dict[str, Any]:
        payload, parse_error = _extract_json_payload(raw_text)
        result = {
            "summary": str(raw_text).strip(),
            "open_ports": [],
            "services": [],
            "topology": {},
            "adaptive_context": {},
            "parse_error": parse_error,
        }
        if isinstance(payload, dict):
            result["summary"] = payload.get("summary") or result["summary"]
            result["open_ports"] = payload.get("open_ports") or payload.get("ports") or []
            result["services"] = payload.get("services") or payload.get("detected_services") or []
            result["topology"] = payload.get("topology") or {}
            result["adaptive_context"] = payload.get("adaptive_context") or {}
            if not result["open_ports"] and isinstance(result["topology"], dict):
                nodes = result["topology"].get("nodes") or []
                if nodes and isinstance(nodes[0], dict):
                    result["open_ports"] = nodes[0].get("open_ports") or []
        return result

    def _has_user_supplied_attack_surface(self) -> bool:
        return any(
            str(self.available_params.get(key) or "").strip()
            for key in (
                "can_interface",
                "bluetooth_mac",
                "wifi_interface",
                "frequency",
                "expected_usb_serial",
                "usb_device_serial",
                "usb_mount_point",
                "local_usb_adb_attached",
            )
        )

    def _clear_attack_surface_gate(self) -> None:
        self.structured_results.pop("attack_surface_gate", None)
        recon = self.structured_results.get("recon")
        if isinstance(recon, dict):
            recon.pop("attack_surface_gate", None)

    def _recon_has_network_attack_surface(self, recon: Dict[str, Any]) -> bool:
        if not isinstance(recon, dict):
            return False
        if recon.get("open_ports") or recon.get("services"):
            return True
        topology = recon.get("topology") or {}
        if isinstance(topology, dict):
            for node in topology.get("nodes") or []:
                if not isinstance(node, dict):
                    continue
                if node.get("open_ports") or node.get("services"):
                    return True
        adaptive = recon.get("adaptive_context") or {}
        if isinstance(adaptive, dict):
            if adaptive.get("detected_services") or adaptive.get("auth_contexts"):
                return True
        return False

    def _build_no_attack_surface_gate(self, recon: Dict[str, Any]) -> Dict[str, Any]:
        supplied = {
            key: value
            for key, value in self.available_params.items()
            if key != "target_ip" and str(value or "").strip()
        }
        missing_inputs: List[str] = []
        if not recon.get("open_ports"):
            missing_inputs.append("open_ports")
        if not recon.get("services"):
            missing_inputs.append("services")
        for param_key in ("can_interface", "bluetooth_mac", "wifi_interface", "frequency"):
            if not supplied.get(param_key):
                missing_inputs.append(param_key)
        if not (
            supplied.get("expected_usb_serial")
            or supplied.get("usb_device_serial")
            or supplied.get("local_usb_adb_attached")
        ):
            missing_inputs.append("usb_adb_attached")
        if not supplied.get("usb_mount_point"):
            missing_inputs.append("usb_mount_point")
        if not missing_inputs:
            missing_inputs.append("target_service")
        supplied_summary = "、".join(f"{key}={value}" for key, value in supplied.items()) or "无"
        return {
            "blocked": True,
            "blocked_reason": "insufficient_attack_surface",
            "next_action": "skip_to_assess",
            "next_phase": "assess",
            "reason": (
                "基础/细粒度侦察未发现开放端口或服务，且未提供 CAN、蓝牙、Wi-Fi、RF、USB/ADB 等额外验证参数。"
                "继续规划和执行 PoC 不具备可验证攻击面。"
            ),
            "missing_inputs": missing_inputs,
            "observed": {
                "open_ports": recon.get("open_ports") or [],
                "services": recon.get("services") or [],
                "available_params": supplied,
                "supplied_summary": supplied_summary,
            },
        }

    def _apply_attack_surface_gate(self, recon: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if self._recon_has_network_attack_surface(recon) or self._has_user_supplied_attack_surface():
            return None
        gate = self._build_no_attack_surface_gate(recon)
        recon["attack_surface_gate"] = gate
        self.structured_results["attack_surface_gate"] = gate
        self._record_supervisor_event(
            "attack_surface_gate",
            gate["reason"],
            severity="warning",
            phase="recon",
        )
        return gate

    def _build_minimal_no_surface_report(self, gate: Dict[str, Any]) -> str:
        missing = "、".join(gate.get("missing_inputs") or [])
        observed = gate.get("observed") or {}
        supplied_summary = observed.get("supplied_summary") or "无"
        supplied_note = (
            f"用户已提供的额外参数：{supplied_summary}。"
            if supplied_summary != "无"
            else "用户未提供 CAN、蓝牙、Wi-Fi、RF、USB/ADB 等额外验证参数。"
        )
        return (
            f"# 智能网联汽车安全评估报告\n\n"
            f"## 执行摘要\n"
            f"本次针对目标 `{self.target_name}` (`{self.target_ip}`) 执行自动化侦察后，"
            f"未发现开放端口、可识别服务或可直接验证的网络攻击面；{supplied_note}"
            f"因此平台未继续执行 PoC 利用验证，以避免无证据、无目标的无效扫描。\n\n"
            f"## 总体风险评级\n"
            f"- **UNKNOWN / LOW EVIDENCE**：当前证据不足以证明存在漏洞，也不足以证明目标安全。\n\n"
            f"## 实际测试范围\n"
            f"- 已执行：基础侦察与攻击面充分性判断。\n"
            f"- 未执行：PoC 利用验证、多 Agent 攻击路径执行、物理接口验证。\n\n"
            f"## 阻断原因\n"
            f"{gate.get('reason')}\n\n"
            f"## 建议补充输入\n"
            f"{missing}\n\n"
            f"## 结论\n"
            f"本次扫描形成的是“无可验证攻击面”的最简评估报告。若需要继续验证，请补充明确攻击面参数，或确认目标处于同网段、可达、已完成协议唤醒。"
        )

    def _normalize_attack_plan(self, raw_text: str) -> Dict[str, Any]:
        payload, parse_error = _extract_json_payload(raw_text)
        items = _normalize_plan_items(payload)
        
        # If normal normalization failed to find items, try heuristic extraction from raw text
        if not items:
            items = self._heuristic_extract_plan_items(raw_text)
            
        return {
            "items": items,
            "summary": str(raw_text).strip(),
            "parse_error": parse_error,
            "item_count": len(items),
        }

    def _usb_adb_resources_ready(self) -> bool:
        return bool(
            self.available_params.get("expected_usb_serial")
            or self.available_params.get("local_usb_adb_attached")
        )

    def _ensure_usb_adb_plan_item(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        if not self._usb_adb_resources_ready():
            return plan
        items = list(plan.get("items") or [])
        if any(str(item.get("poc_name") or "") == "network/01_USB_ADB_Debug.py" for item in items):
            return plan
        usb_params: Dict[str, Any] = {
            "target_ip": self.target_ip,
            "allow_single_attached_match": True,
        }
        if self.available_params.get("expected_usb_serial"):
            usb_params["expected_usb_serial"] = self.available_params["expected_usb_serial"]
            reason = "本机仅连接 1 台 USB ADB 设备，优先验证有线调试接口。"
        next_step = max([int(item.get("step") or 0) for item in items] or [0]) + 1
        items.insert(0, asdict(AttackPlanItem(
            step=next_step,
            poc_name="network/01_USB_ADB_Debug.py",
            parameters=usb_params,
            strategy="local_usb_adb_recon",
            reason=reason,
            status="pending",
        )))
        for index, item in enumerate(items, start=1):
            item["step"] = index
        plan["items"] = items
        plan["item_count"] = len(items)
        self._record_supervisor_event(
            "usb_adb_plan_injected",
            "检测到本机 USB ADB 可用，已自动将 network/01_USB_ADB_Debug.py 加入 Agent 攻击计划。",
            phase="decision",
        )
        return plan

    def _heuristic_extract_plan_items(self, text: str) -> List[Dict[str, Any]]:
        """从非结构化文本中启发式提取 PoC 路径和参数"""
        items = []
        import re
        # 查找 PoC 路径模式 (例如 network/ssh_brute.py)
        # 排除已经包含在 md 代码块中的内容，或者只是简单的文件名
        poc_match_pattern = r'([a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+\.py)'
        found_paths = re.findall(poc_match_pattern, text)
        
        # 去重并构建 items
        seen = set()
        step_id = 1
        for path in found_paths:
            if path in seen:
                continue
            seen.add(path)
            
            # 尝试在路径附近查找可能的参数或描述
            # 这里简单起见，仅提取路径
            items.append(asdict(AttackPlanItem(
                step=step_id,
                poc_name=path,
                parameters={"target_ip": self.target_ip},
                strategy="heuristic_recovery",
                reason="Auto-extracted from natural language response",
                status="pending"
            )))
            step_id += 1
            
        return items

    def _normalize_execution_result(self, raw_text: str) -> Dict[str, Any]:
        payload, parse_error = _extract_json_payload(raw_text)
        items = _normalize_execution_items(payload)
        for item in items:
            if item["vulnerable"]:
                self._register_finding(
                    item["poc_name"],
                    evidence=item.get("evidence", ""),
                    error=item.get("error", ""),
                    source="execution_summary",
                )
        return {
            "items": items,
            "summary": str(raw_text).strip(),
            "parse_error": parse_error,
            "item_count": len(items),
        }

    def _normalize_planner_result(self, raw_text: str) -> Dict[str, Any]:
        payload, parse_error = _extract_json_payload(raw_text)
        result = {
            "strategy_summary": "",
            "steps": [],
            "guardrails": [],
            "parse_error": parse_error,
            "summary": str(raw_text).strip(),
        }
        if isinstance(payload, dict):
            # Also check for 'strategy' or other keys if 'steps' is missing but something else is there
            steps = payload.get("steps") or payload.get("plan") or payload.get("items") or []
            normalized_steps = []
            for index, step in enumerate(steps, start=1):
                if not isinstance(step, dict):
                    # Handle string-only steps
                    if isinstance(step, str):
                        normalized_steps.append({
                            "step": index,
                            "title": step[:50],
                            "objective": step,
                            "success_criteria": "完成步骤描述",
                            "depends_on": [],
                        })
                    continue
                normalized_steps.append({
                    "step": step.get("step") or index,
                    "title": step.get("title") or step.get("name") or step.get("desc", f"步骤 {index}")[:50],
                    "objective": step.get("objective") or step.get("goal") or step.get("desc") or "",
                    "success_criteria": step.get("success_criteria") or step.get("criteria") or "无",
                    "depends_on": step.get("depends_on") or [],
                })
            result["strategy_summary"] = payload.get("strategy_summary") or payload.get("summary") or payload.get("strategy") or ""
            result["steps"] = normalized_steps
            result["guardrails"] = payload.get("guardrails") or payload.get("constraints") or []
        return result

    def _normalize_reflector_phase(self, phase: Any) -> str:
        normalized = str(phase or "").strip().lower()
        aliases = {
            "": "",
            "none": "",
            "recon": "recon",
            "reconnaissance": "recon",
            "planner": "planner",
            "plan": "planner",
            "planning": "planner",
            "decision": "decision",
            "decider": "decision",
            "weaponize": "weaponize",
            "weaponization": "weaponize",
            "weaponizer": "weaponize",
            "execute": "execute",
            "executor": "execute",
            "execution": "execute",
            "reflector": "reflector",
            "reflect": "reflector",
            "assess": "assess",
            "assessment": "assess",
            "assessment_agent": "assess",
        }
        return aliases.get(normalized, "")

    def _normalize_reflector_result(self, raw_text: str) -> Dict[str, Any]:
        payload, parse_error = _extract_json_payload(raw_text)
        result = {
            "summary": str(raw_text).strip(),
            "execution_effective": True,
            "evidence_sufficient": True,
            "outcome_status": "other",
            "issues": [],
            "next_action": "continue",
            "next_phase": "",
            "rerun_mode": "from_phase",
            "focus_steps": [],
            "focus_pocs": [],
            "reentry_required": False,
            "reason": "",
            "parse_error": parse_error,
        }
        if isinstance(payload, dict):
            result["summary"] = str(payload.get("summary") or result["summary"]).strip()
            result["execution_effective"] = bool(payload.get("execution_effective", result["execution_effective"]))
            result["evidence_sufficient"] = bool(payload.get("evidence_sufficient", result["evidence_sufficient"]))
            result["outcome_status"] = str(payload.get("outcome_status") or result["outcome_status"]).strip().lower()
            raw_issues = payload.get("issues") or []
            issues: List[Dict[str, Any]] = []
            if isinstance(raw_issues, list):
                for issue in raw_issues:
                    if isinstance(issue, dict):
                        issues.append({
                            "category": str(issue.get("category") or "other").strip().lower(),
                            "severity": str(issue.get("severity") or "medium").strip().lower(),
                            "reason": str(issue.get("reason") or "").strip(),
                            "impact": str(issue.get("impact") or "").strip(),
                            "suggestion": str(issue.get("suggestion") or "").strip(),
                        })
                    elif isinstance(issue, str) and issue.strip():
                        issues.append({
                            "category": "other",
                            "severity": "medium",
                            "reason": issue.strip(),
                            "impact": "",
                            "suggestion": "",
                        })
            result["issues"] = issues
            result["next_action"] = str(payload.get("next_action") or result["next_action"]).strip().lower()
            result["next_phase"] = self._normalize_reflector_phase(payload.get("next_phase"))
            result["rerun_mode"] = str(payload.get("rerun_mode") or result["rerun_mode"]).strip().lower()
            raw_focus_steps = payload.get("focus_steps") or []
            if isinstance(raw_focus_steps, list):
                focus_steps: List[int] = []
                for step in raw_focus_steps:
                    try:
                        focus_steps.append(int(step))
                    except Exception:
                        continue
                result["focus_steps"] = sorted(set(focus_steps))
            raw_focus_pocs = payload.get("focus_pocs") or []
            if isinstance(raw_focus_pocs, list):
                result["focus_pocs"] = sorted({
                    str(poc).strip() for poc in raw_focus_pocs if str(poc).strip()
                })
            result["reentry_required"] = bool(payload.get("reentry_required", result["reentry_required"]))
            result["reason"] = str(payload.get("reason") or "").strip()

        if result["next_phase"] == "execute" and (result["focus_steps"] or result["focus_pocs"]):
            result["rerun_mode"] = "targeted"

        # Only execute supports targeted reruns. Earlier phases must restart from phase.
        if result["next_phase"] in {"recon", "planner", "decision", "weaponize"}:
            result["rerun_mode"] = "from_phase"
            if result["next_action"] == "continue" and result["reentry_required"]:
                result["next_action"] = "retry"

        if (
            not result["reentry_required"]
            and result["next_action"] in {"retry", "branch"}
            and result["next_phase"] in {"recon", "planner", "decision", "weaponize", "execute"}
        ):
            result["reentry_required"] = True

        if (
            not result["reentry_required"]
            and (not result["execution_effective"] or not result["evidence_sufficient"])
            and result["next_phase"] in {"recon", "planner", "decision", "weaponize", "execute"}
        ):
            result["reentry_required"] = True

        if not result["reentry_required"] and (
            not result["execution_effective"]
            or not result["evidence_sufficient"]
            or result["outcome_status"] in {"execution_failed", "failed", "invalid", "no_evidence"}
        ):
            audit_text = " ".join([
                result.get("summary") or "",
                result.get("reason") or "",
                _safe_json_dumps(result.get("issues") or []),
            ]).lower()
            result["next_action"] = "retry"
            if any(token in audit_text for token in [
                "侦察", "连通性", "前置", "协议唤醒", "recon", "connectivity", "precondition", "discovery"
            ]):
                result["next_phase"] = "recon"
                result["rerun_mode"] = "from_phase"
            elif any(token in audit_text for token in ["计划", "编排", "planner", "decision", "attack plan"]):
                result["next_phase"] = "decision"
                result["rerun_mode"] = "from_phase"
            else:
                result["next_phase"] = "execute"
                result["rerun_mode"] = "targeted" if (result["focus_steps"] or result["focus_pocs"]) else "from_phase"
            result["reentry_required"] = True
            result["reason"] = result["reason"] or "Reflector 判定执行无效或证据不足，系统自动触发保守回跳。"

        return result

    def _fallback_planner_result(self) -> Dict[str, Any]:
        recon = self.structured_results.get("recon", {})
        services = recon.get("services") or []
        open_ports = recon.get("open_ports") or []
        service_hint = "、".join(map(str, services[:3])) if services else "开放端口"
        return {
            "strategy_summary": f"围绕 {service_hint} 进行分阶段验证，优先侦察确认，再执行利用，最后输出风险评估。",
            "steps": [
                {"step": 1, "title": "确认暴露面", "objective": f"确认开放端口与服务指纹: {open_ports}", "success_criteria": "得到稳定服务画像", "depends_on": []},
                {"step": 2, "title": "筛选可用 PoC", "objective": "结合可用资源过滤不匹配的攻击向量", "success_criteria": "得到去重后的攻击计划", "depends_on": [1]},
                {"step": 3, "title": "执行验证", "objective": "逐项执行利用并记录证据", "success_criteria": "至少得到成功/失败/阻断证据", "depends_on": [2]},
                {"step": 4, "title": "风险总结", "objective": "汇总漏洞与失败原因，生成评估结论", "success_criteria": "得到最终报告", "depends_on": [3]},
            ],
            "guardrails": [
                "避免重复调用同一工具",
                "连续失败时切换策略或终止",
                "不要让错误结果扩散到后续阶段",
            ],
            "parse_error": None,
            "summary": "fallback planner",
        }

    def _build_execution_context(self) -> str:
        return (
            f"侦察结果(JSON):\n{_safe_json_dumps(self.structured_results['recon'])}\n\n"
            f"攻击计划(JSON):\n{_safe_json_dumps(self.structured_results['attack_plan'])}"
        )

    def _safety_check_for_plan_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        return call_mcp_tool(
            "check_safety",
            {
                "target_ip": self.target_ip,
                "poc_name": item.get("poc_name"),
                "protocol": item.get("protocol") or item.get("strategy") or "",
            },
            on_log=self._add_log,
            tool_state=self.executor_agent.tool_state,
        )

    def _default_execution_params(self) -> Dict[str, Any]:
        params: Dict[str, Any] = {"target_ip": self.target_ip}
        if self.candidate_ports:
            params["candidate_ports"] = self.candidate_ports
        for key in (
            "can_interface",
            "can_bitrate",
            "bluetooth_mac",
            "bd_addr",
            "target_mac",
            "wifi_interface",
            "interface",
            "frequency",
            "expected_usb_serial",
            "usb_device_serial",
            "usb_mount_point",
        ):
            value = self.available_params.get(key)
            if str(value or "").strip():
                params[key] = value
        if params.get("bluetooth_mac"):
            params.setdefault("bd_addr", params["bluetooth_mac"])
            params.setdefault("target_mac", params["bluetooth_mac"])
        if params.get("wifi_interface"):
            params.setdefault("interface", params["wifi_interface"])
        return params

    def _normalize_strategy_name(self, strategy: str) -> str:
        normalized = (strategy or "default").strip().lower()
        aliases = {
            "adaptive": "adaptive_throttle",
            "throttle": "adaptive_throttle",
            "throttled": "adaptive_throttle",
            "retry": "retry_once",
            "retry_once": "retry_once",
            "alternate": "alternate_params",
            "alternate_params": "alternate_params",
            "skip": "skip_on_warning",
            "skip_on_warning": "skip_on_warning",
        }
        return aliases.get(normalized, normalized)

    def _build_execution_branches(self, item: Dict[str, Any], safety: Dict[str, Any]) -> List[Dict[str, Any]]:
        base_params = dict(item.get("parameters") or {})
        strategy = self._normalize_strategy_name(item.get("strategy") or safety.get("strategy") or "default")
        branches: List[Dict[str, Any]] = []

        def add_branch(name: str, params: Dict[str, Any], cooldown_s: float = 0.0, note: str = "", continue_on_error: bool = True):
            branches.append({
                "name": name,
                "params": params,
                "cooldown_s": cooldown_s,
                "note": note,
                "continue_on_error": continue_on_error,
            })

        if strategy == "adaptive_throttle":
            add_branch(
                "throttled_primary",
                base_params,
                cooldown_s=float(safety.get("recommended_interval_s") or 0.0),
                note="按自适应策略插入节流间隔后执行",
                continue_on_error=True,
            )
        else:
            add_branch("primary", base_params, note="标准执行分支", continue_on_error=True)

        if strategy in {"retry_once", "alternate_params"}:
            retry_params = dict(base_params)
            current_timeout = retry_params.get("timeout")
            if isinstance(current_timeout, (int, float)):
                retry_params["timeout"] = round(float(current_timeout) * 1.5, 2)
            elif isinstance(safety.get("recommended_interval_s"), (int, float)):
                retry_params["timeout"] = max(3.0, round(float(safety["recommended_interval_s"]) + 1.0, 2))
            retry_params["strategy_branch"] = strategy
            add_branch(
                "retry_adjusted",
                retry_params,
                cooldown_s=0.5,
                note="基于失败或策略要求触发的备用分支",
                continue_on_error=False,
            )

        if strategy == "skip_on_warning":
            add_branch(
                "warn_only",
                base_params,
                note="仅保留告警上下文，不执行利用",
                continue_on_error=False,
            )

        return branches

    def _run_execution_branch(
        self,
        item: Dict[str, Any],
        branch: Dict[str, Any],
        safety: Dict[str, Any],
    ) -> Dict[str, Any]:
        poc_name = item.get("poc_name") or "unknown"
        params = self._default_execution_params()
        params.update(dict(branch.get("params") or {}))
        if branch.get("cooldown_s", 0) > 0:
            time.sleep(float(branch["cooldown_s"]))
        if branch["name"] == "warn_only":
            return {
                "success": False,
                "vulnerable": False,
                "blocked": True,
                "error": safety.get("reason", "blocked by strategy"),
                "evidence": "",
                "logs": [],
                "strategy_branch": branch["name"],
            }
        params.setdefault("target_ip", self.target_ip)
        params["execution_branch"] = branch["name"]
        high_risk, meta = self._is_high_risk_poc(str(poc_name))
        if high_risk and params.get("allow_disruptive") not in {True, "true", "True", "1", 1}:
            approved, wait_seconds = self._prompt_high_risk_approval(str(poc_name), meta, params)
            self.manual_review_wait_seconds += wait_seconds
            if not approved:
                return {
                    "success": False,
                    "blocked": True,
                    "requires_approval": True,
                    "error": "high-risk PoC skipped by operator",
                    "vulnerable": False,
                    "evidence": "",
                    "logs": [],
                    "strategy_branch": branch["name"],
                    "manual_review_wait_seconds": wait_seconds,
                }
            params["allow_disruptive"] = True

        result = call_mcp_tool(
            "run_poc",
            {
                "poc_name": poc_name,
                "params": params,
            },
            on_log=self._add_log,
            tool_state=self.executor_agent.tool_state,
        )
        if (
            bool(result.get("requires_human_review"))
            and str(result.get("verification_status") or "") == "pending_manual_review"
        ):
            result, wait_seconds = self._prompt_manual_verdict(str(poc_name), result)
            self.manual_review_wait_seconds += wait_seconds
        return result

    def _summarize_execution_items(self, items: List[Dict[str, Any]]) -> str:
        lines = []
        for item in items:
            status = item.get("status", "unknown")
            poc_name = item.get("poc_name", "unknown")
            if item.get("vulnerable"):
                lines.append(f"- {poc_name} [{item.get('branch', 'primary')}]: vulnerable | evidence={item.get('evidence') or 'n/a'}")
            elif item.get("error"):
                lines.append(f"- {poc_name} [{item.get('branch', 'primary')}]: {status} | error={item.get('error')}")
            else:
                lines.append(f"- {poc_name} [{item.get('branch', 'primary')}]: {status}")
        return "\n".join(lines) if lines else "未返回任何执行结果"

    def _execute_plan_stepwise(self) -> Tuple[str, Dict[str, Any]]:
        plan_items = self.structured_results.get("attack_plan", {}).get("items") or []
        
        if not plan_items:
            self._add_log({"type": "warning", "message": "[Executor Agent] 警告: 攻击计划列表为空，无法执行任何 PoC。请检查决策 Agent 是否正确解析了侦察结果。"})
        elif any(item.get("strategy") == "heuristic_recovery" for item in plan_items):
            self._add_log({"type": "warning", "message": f"[Executor Agent] 提示: 决策 Agent 输出非标准 JSON，已通过启发式算法尝试恢复 {len(plan_items)} 条攻击路径。"})

        execution_items: List[Dict[str, Any]] = []
        consecutive_errors = 0

        for item in plan_items:
            step = item.get("step")
            poc_name = item.get("poc_name")
            if item.get("status") in {"skipped_by_supervisor", "skipped_by_reflector_reentry"}:
                execution_items.append(asdict(ExecutionResultItem(
                    step=step or len(execution_items) + 1,
                    poc_name=poc_name or f"step_{len(execution_items) + 1}",
                    status=item.get("status") or "skipped",
                    vulnerable=False,
                    evidence="",
                    error=item.get("reason", ""),
                    strategy=item.get("strategy") or "default",
                )))
                continue

            self._add_log({
                "type": "info",
                "message": f"[Executor-Step] 开始执行步骤 {step}: {poc_name}",
            })
            self._console(f"[AGENT][EXEC][{len(execution_items) + 1}/{len(plan_items)}] start {poc_name}")

            safety = self._safety_check_for_plan_item(item)
            if safety.get("should_run") is False:
                execution_items.append(asdict(ExecutionResultItem(
                    step=step or len(execution_items) + 1,
                    poc_name=poc_name or f"step_{len(execution_items) + 1}",
                    status="blocked",
                    vulnerable=False,
                    evidence="",
                    error=safety.get("reason", "blocked by safety policy"),
                    strategy=safety.get("strategy") or item.get("strategy") or "default",
                    branch="blocked",
                )))
                item["status"] = "blocked"
                self._console(f"[AGENT][EXEC][{len(execution_items)}/{len(plan_items)}] blocked {poc_name}: {safety.get('reason', '')}")
                consecutive_errors = 0
                continue

            branches = self._build_execution_branches(item, safety)
            branch_results: List[Dict[str, Any]] = []
            status = "error"
            error = ""
            vulnerable = False
            evidence = ""
            active_branch = "primary"

            for branch in branches:
                active_branch = branch["name"]
                self._add_log({
                    "type": "info",
                    "message": f"[Executor-Step] 分支 {active_branch} 执行中: {poc_name}",
                })
                result = self._run_execution_branch(item, branch, safety)
                requires_human_review = bool(result.get("requires_human_review")) or result.get("verification_status") == "pending_manual_review"
                result_vulnerable = result.get("vulnerable")
                branch_trace_id = (
                    str(result.get("trace_id") or "").strip()
                    or str(self.trace_id or "").strip()
                    or "agent_auto"
                )
                branch_result = {
                    "branch": active_branch,
                    "success": bool(result.get("success", not result.get("error"))),
                    "blocked": bool(result.get("blocked")),
                    "vulnerable": result_vulnerable if result_vulnerable is not None else None,
                    "error": result.get("error", ""),
                    "evidence": result.get("evidence", ""),
                    "strategy_branch": result.get("strategy_branch") or branch.get("name"),
                    "requires_human_review": requires_human_review,
                    "verification_status": result.get("verification_status", ""),
                    "manual_review": result.get("manual_review", {}),
                    "manual_review_wait_seconds": float(result.get("manual_review_wait_seconds") or 0),
                    "trace_id": branch_trace_id,
                    "poc_id": result.get("poc_id") or poc_name,
                }
                branch_results.append(branch_result)

                error = branch_result["error"]
                vulnerable = branch_result["vulnerable"]
                evidence = branch_result["evidence"]

                if branch_result["blocked"]:
                    status = "blocked"
                    break
                if requires_human_review:
                    status = "pending_manual_review"
                    consecutive_errors = 0
                    break
                if vulnerable:
                    status = "vulnerable"
                    consecutive_errors = 0
                    break
                if not error:
                    status = "completed"
                    consecutive_errors = 0
                    break

                status = "error"
                consecutive_errors += 1
                if not branch.get("continue_on_error", True):
                    break

            if vulnerable:
                self._register_finding(
                    poc_name or "",
                    evidence=evidence,
                    error="",
                    source="stepwise_executor",
                    parameters=item.get("parameters") or {},
                )

            execution_items.append(asdict(ExecutionResultItem(
                step=step or len(execution_items),
                poc_name=poc_name or f"step_{len(execution_items)}",
                status=status,
                vulnerable=vulnerable,
                evidence=evidence,
                error=error,
                strategy=safety.get("strategy") or item.get("strategy") or "default",
                branch=active_branch,
                requires_human_review=status == "pending_manual_review",
                verification_status=str(next((br.get("verification_status") for br in branch_results if br.get("requires_human_review")), "") or ""),
                manual_review=dict(next((br.get("manual_review") for br in branch_results if br.get("requires_human_review")), None) or {}),
            )))
            execution_items[-1]["branch_results"] = branch_results
            item["status"] = status
            self._console(
                f"[AGENT][EXEC][{len(execution_items)}/{len(plan_items)}] done {poc_name} "
                f"status={status} vulnerable={vulnerable} error={error or 'n/a'}"
            )

            if consecutive_errors >= SUPERVISOR_LIMITS["max_cascading_errors"]:
                if self.baseline_replay_pocs:
                    self._record_supervisor_event(
                        "execution_error_spread",
                        f"连续 {consecutive_errors} 个错误，但当前为实验 baseline replay 模式，继续执行后续 PoC 以保证覆盖率统计完整。",
                        severity="warning",
                        phase="execute",
                    )
                    consecutive_errors = 0
                    continue
                self._add_log({"type": "warning", "message": f"[Supervisor] 检测到连续 {consecutive_errors} 个错误，触发 Reflector Agent..."})
                
                reflector_context = (
                    f"侦察数据:\n{_safe_json_dumps(self.structured_results.get('recon', {}))}\n\n"
                    f"原攻击计划:\n{_safe_json_dumps(self.structured_results.get('attack_plan', {}))}\n\n"
                    f"近期执行错误记录:\n{_safe_json_dumps(execution_items[-consecutive_errors:])}"
                )
                
                reflection_result = self.reflector_agent.call(
                    f"请分析连续执行失败的原因，并指出后续测试调整建议或直接建议中止不可达的路径。",
                    context=reflector_context
                )
                
                self._record_supervisor_event(
                    "execution_error_spread",
                    f"连续错误触发安全熔断。Reflector 建议:\n{reflection_result[:300]}...",
                    severity="error",
                    phase="execute",
                )
                self.structured_results["execution"] = {
                    "items": execution_items,
                    "summary": self._summarize_execution_items(execution_items),
                    "parse_error": None,
                    "item_count": len(execution_items),
                    "reflection": reflection_result
                }
                self._prune_attack_plan_after_failures([item for item in execution_items if item.get("error")])
                break

        structured = {
            "items": execution_items,
            "summary": self._summarize_execution_items(execution_items),
            "parse_error": None,
            "item_count": len(execution_items),
        }
        return structured["summary"], structured

    def _get_phase_record(self, phase: str) -> Optional[dict]:
        return next((r for r in self.phase_records if r["phase"] == phase), None)

    def _require_phase_success(self, phase: str):
        record = self._get_phase_record(phase)
        if record and record.get("status") == "error":
            raise RuntimeError(f"phase {phase} failed validation: {record.get('error') or 'unknown error'}")

    def _record_supervisor_event(self, scope: str, message: str, severity: str = "warning", phase: str = ""):
        event = {
            "scope": scope,
            "severity": severity,
            "message": message,
            "phase": phase,
            "timestamp": _utc_timestamp(),
        }
        supervisor = self.structured_results.setdefault("supervisor", {"events": [], "metrics": {}, "adjustments": []})
        supervisor.setdefault("events", []).append(event)
        self._refresh_supervisor_metrics()
        self._add_log({
            "type": "warning" if severity != "info" else "info",
            "message": f"[Supervisor] {message}",
        })

    def _record_supervisor_adjustment(
        self,
        adjustment_type: str,
        message: str,
        affected_steps: Optional[List[int]] = None,
        affected_pocs: Optional[List[str]] = None,
    ):
        adjustment = {
            "type": adjustment_type,
            "message": message,
            "affected_steps": affected_steps or [],
            "affected_pocs": affected_pocs or [],
            "timestamp": _utc_timestamp(),
        }
        supervisor = self.structured_results.setdefault("supervisor", {"events": [], "metrics": {}, "adjustments": []})
        supervisor.setdefault("adjustments", []).append(adjustment)
        self._refresh_supervisor_metrics()

    def _refresh_supervisor_metrics(self):
        supervisor = self.structured_results.setdefault("supervisor", {"events": [], "metrics": {}, "adjustments": []})
        events = supervisor.get("events") or []
        adjustments = supervisor.get("adjustments") or []
        execution_items = self.structured_results.get("execution", {}).get("items") or []
        attack_plan_items = self.structured_results.get("attack_plan", {}).get("items") or []

        def _count_events(scope: str) -> int:
            return sum(1 for event in events if event.get("scope") == scope)

        metrics = {
            "total_events": len(events),
            "repeat_tool_calls": _count_events("repeat_tool_call"),
            "no_progress_events": _count_events("no_progress"),
            "cascading_error_events": _count_events("cascading_errors") + _count_events("execution_error_spread"),
            "planner_fallbacks": _count_events("planner_fallback"),
            "deduplicated_steps": sum(len(item.get("affected_steps") or []) for item in adjustments if item.get("type") == "deduplicate_plan"),
            "pruned_steps": sum(len(item.get("affected_steps") or []) for item in adjustments if item.get("type") == "prune_after_failures"),
            "execution_errors": sum(1 for item in execution_items if item.get("error")),
            "confirmed_findings": sum(1 for item in execution_items if item.get("vulnerable")),
            "skipped_plan_steps": sum(1 for item in attack_plan_items if item.get("status") == "skipped_by_supervisor"),
        }
        supervisor["metrics"] = metrics

    def _get_poc_inventory_context(self) -> str:
        """扫描 pocs 目录并返回分类后的文件名清单（降级备用）。"""
        from poc_catalog import is_executable_poc_name

        inventory = {}
        pocs_root = os.path.join(os.path.dirname(__file__), "pocs")
        if not os.path.exists(pocs_root):
            return "PoC 仓库为空或路径不存在。"

        for root, dirs, files in os.walk(pocs_root):
            rel_root = os.path.relpath(root, pocs_root)
            py_files = [
                f for f in files
                if is_executable_poc_name(os.path.join(rel_root, f) if rel_root != "." else f)
            ]
            if py_files:
                category = os.path.basename(root)
                inventory[category] = py_files

        lines = ["【可用 PoC 脚本库清单（仅文件名，优先使用下方元数据表）】"]
        for cat, files in sorted(inventory.items()):
            lines.append(f"  - 分类: {cat}")
            for f in sorted(files):
                lines.append(f"    * {cat}/{f}")
        return "\n".join(lines)

    def _build_decision_poc_context(self, recon_data: Optional[Dict[str, Any]] = None) -> str:
        """决策用 PoC 上下文：端口映射 + poc_coverage 元数据 + Global 已检出优先复验。"""
        from agent_poc_catalog_context import build_decision_poc_context

        raw_recon = recon_data if isinstance(recon_data, dict) else self.structured_results.get("recon")
        recon_data = raw_recon if isinstance(raw_recon, dict) else {}
        open_ports = recon_data.get("open_ports") or []
        global_vulns = recon_data.get("global_vulnerable_pocs") or []
        try:
            return build_decision_poc_context(
                available_params=self.available_params,
                open_ports=open_ports,
                global_vulnerable_pocs=global_vulns,
                coverage_path=self.poc_coverage_path or None,
            )
        except Exception as exc:
            logger.warning("[Orchestrator] decision poc context fallback: %s", exc)
            return self._get_poc_inventory_context()

    def _merge_agent_supervisor_events(self, agent: QwenAgent, phase: str):
        for event in getattr(agent, "supervisor_events", []) or []:
            self._record_supervisor_event(
                event.get("scope", "agent_supervision"),
                event.get("message", ""),
                severity=event.get("severity", "warning"),
                phase=phase,
            )

    def _run_planner(self):
        recon = self.structured_results.get("recon", {})
        open_ports = recon.get("open_ports") or []
        services = recon.get("services") or []
        reflector_focus_ctx = self._build_reflector_focus_context()
        
        # 确保侦察结果不为空
        if not recon or not any([open_ports, services, recon.get("topology")]):
            logger.warning("[Planner] 侦察结果为空或无效，将生成默认规划")
            recon = {"open_ports": [], "services": [], "topology": {"has_security_gateway": False}}
            open_ports = []
            services = []
        
        recon_summary = "目前侦察结果为空，请安排初始扫描任务。"
        if open_ports:
            recon_summary = f"侦察阶段已成功，发现以下开放端口: {open_ports}。检测到服务: {services}。"
            
        planner_raw = self.planner_agent.call(
            (
                f"为目标 {self.target_ip} 生成执行纲要。提示: {recon_summary} 请基于这些发现编排具体的渗透路径。"
                + (
                    " 当前为 Reflector 触发的局部重规划，请尽量保留既有合理阶段，只补充或修正必要步骤。"
                    if reflector_focus_ctx else ""
                )
            ),
            context=(
                f"{self._build_available_params_context()}\n\n"
                f"侦察结果(详细JSON):\n{_safe_json_dumps(recon)}"
                + (f"\n\n{reflector_focus_ctx}" if reflector_focus_ctx else "")
            ),
        )
        planner_structured = self._normalize_planner_result(planner_raw)
        if not planner_structured.get("steps"):
            planner_structured = self._fallback_planner_result()
            self._record_supervisor_event(
                "planner_fallback",
                "规划 Agent 未返回有效步骤，已回退到内置执行纲要。",
                phase="planner",
            )
        self.structured_results["planner"] = planner_structured
        return planner_raw, planner_structured

    def _supervise_attack_plan(self):
        items = self.structured_results.get("attack_plan", {}).get("items") or []
        if not items:
            return

        deduped = []
        seen = set()
        removed = 0
        for item in items:
            signature = (
                item.get("poc_name"),
                json.dumps(item.get("parameters") or {}, sort_keys=True, ensure_ascii=False),
            )
            if signature in seen:
                removed += 1
                continue
            seen.add(signature)
            deduped.append(item)

        if removed:
            self.structured_results["attack_plan"]["items"] = deduped
            self.structured_results["attack_plan"]["item_count"] = len(deduped)
            self.attack_plan = _safe_json_dumps(self.structured_results["attack_plan"])
            removed_steps = [item.get("step") for item in items if item not in deduped]
            self._record_supervisor_event(
                "deduplicate_plan",
                f"攻击计划中检测到 {removed} 个重复步骤，已自动去重。",
                phase="decision",
            )
            self._record_supervisor_adjustment(
                "deduplicate_plan",
                f"已移除 {removed} 个重复攻击步骤。",
                affected_steps=[step for step in removed_steps if step is not None],
            )

        current_items = self.structured_results.get("attack_plan", {}).get("items") or deduped
        try:
            from poc_catalog import is_executable_poc_name
        except Exception:
            is_executable_poc_name = None
        if is_executable_poc_name:
            valid_items = []
            invalid_steps = []
            invalid_pocs = []
            for item in current_items:
                poc_name = str(item.get("poc_name") or "").strip()
                if poc_name and is_executable_poc_name(poc_name):
                    valid_items.append(item)
                    continue
                invalid_steps.append(item.get("step"))
                invalid_pocs.append(poc_name or "<empty>")
            if invalid_pocs:
                self.structured_results["attack_plan"]["items"] = valid_items
                self.structured_results["attack_plan"]["item_count"] = len(valid_items)
                self.attack_plan = _safe_json_dumps(self.structured_results["attack_plan"])
                self._record_supervisor_event(
                    "drop_invalid_poc",
                    f"攻击计划中 {len(invalid_pocs)} 个 PoC 不在可执行目录，已阻止执行: {invalid_pocs}",
                    phase="decision",
                )
                self._record_supervisor_adjustment(
                    "drop_invalid_poc",
                    f"已移除不可执行 PoC: {invalid_pocs}",
                    affected_steps=[step for step in invalid_steps if step is not None],
                )

    def _supervise_execution_outcome(self):
        items = self.structured_results.get("execution", {}).get("items") or []
        if not items:
            return
        error_items = [item for item in items if item.get("error")]
        vulnerable_items = [item for item in items if item.get("vulnerable")]
        if len(error_items) >= SUPERVISOR_LIMITS["max_cascading_errors"] and not vulnerable_items:
            self._record_supervisor_event(
                "execution_error_spread",
                "执行阶段出现连续错误且未取得有效漏洞证据，建议停止扩张并优先总结失败原因。",
                severity="error",
                phase="execute",
            )
            self._prune_attack_plan_after_failures(error_items)

        self._refresh_supervisor_metrics()

    def _prune_attack_plan_after_failures(self, error_items: List[Dict[str, Any]]):
        plan_items = self.structured_results.get("attack_plan", {}).get("items") or []
        if not plan_items:
            return

        executed_steps = {
            item.get("step")
            for item in (self.structured_results.get("execution", {}).get("items") or [])
            if item.get("step") is not None
        }
        highest_executed_step = max(executed_steps) if executed_steps else 0

        pruned_steps: List[int] = []
        pruned_pocs: List[str] = []
        for item in plan_items:
            poc_name = item.get("poc_name")
            step = item.get("step")
            if not poc_name or step is None:
                continue
            if item.get("status") == "skipped_by_supervisor":
                continue
            if step > highest_executed_step:
                item["status"] = "skipped_by_supervisor"
                item["reason"] = (item.get("reason") or "") + " | 已因前序步骤连续失败被 Supervisor 剪枝"
                pruned_steps.append(step)
                pruned_pocs.append(poc_name)

        if pruned_steps:
            self.attack_plan = _safe_json_dumps(self.structured_results["attack_plan"])
            self._record_supervisor_event(
                "prune_after_failures",
                f"检测到重复失败后，已自动剪枝 {len(pruned_steps)} 个后续步骤，避免错误扩散。",
                severity="error",
                phase="execute",
            )
            self._record_supervisor_adjustment(
                "prune_after_failures",
                f"已剪枝 {len(pruned_steps)} 个高风险后续步骤。",
                affected_steps=[step for step in pruned_steps if step is not None],
                affected_pocs=pruned_pocs,
            )

    def _build_available_params_context(self) -> str:
        parts = [f"target_ip={self.target_ip}"]
        if "can_interface" in self.available_params:
            parts.append(f"can_interface={self.available_params['can_interface']}")
        else:
            parts.append("can_interface=未提供（跳过所有 CAN/ISO-TP 相关 PoC）")
        if "bluetooth_mac" in self.available_params:
            parts.append(f"bluetooth_mac={self.available_params['bluetooth_mac']}")
        else:
            parts.append("bluetooth_mac=未提供（跳过所有蓝牙/BLE 相关 PoC）")
        if "wifi_interface" in self.available_params:
            parts.append(f"wifi_interface={self.available_params['wifi_interface']}")
        else:
            parts.append("wifi_interface=未提供（跳过所有无线嗅探相关 PoC）")
        if self._usb_adb_resources_ready():
            if self.available_params.get("expected_usb_serial"):
                parts.append(
                    f"expected_usb_serial={self.available_params['expected_usb_serial']}（本机 USB ADB，可执行 01_USB_ADB_Debug）"
                )
            else:
                parts.append(f"local_usb_adb_attached=true（唯一设备 serial={self.available_params.get('expected_usb_serial', '')}）")
        else:
            reason = self.available_params.get("usb_adb_block_reason") or "未连接或连接多台 USB 设备"
            parts.append(f"本机 USB ADB=不可用（{reason}；跳过 network/01_USB_ADB_Debug.py）")
        return "【可用资源】\n" + "\n".join(f"  - {p}" for p in parts)

    def _build_reflector_focus_context(self) -> str:
        reflector = self.structured_results.get("reflector", {}) or {}
        if not reflector.get("reentry_required"):
            return ""
        issues = reflector.get("issues") or []
        issue_lines = []
        for issue in issues[:5]:
            if not isinstance(issue, dict):
                continue
            issue_lines.append(
                f"- {issue.get('category', 'other')}: {issue.get('reason', '')} | 建议: {issue.get('suggestion', '')}"
            )
        safety_lines: List[str] = []
        try:
            plans = self._plan_reentry_safety(reflector)
        except Exception:
            plans = []
        for plan in plans:
            sub = plan.get("substitute_probe") or {}
            sub_hint = f" → 替换探针:{sub.get('probe')}({sub.get('mode')})" if sub else ""
            safety_lines.append(
                f"- {plan.get('poc_id')}: 风险={plan['risk_state'].get('level')} "
                f"策略={plan.get('strategy')}{sub_hint} | {plan.get('rationale')}"
            )
        return (
            "【Reflector 重入指令】\n"
            f"- next_action={reflector.get('next_action')}\n"
            f"- next_phase={reflector.get('next_phase')}\n"
            f"- rerun_mode={reflector.get('rerun_mode')}\n"
            f"- focus_steps={reflector.get('focus_steps') or []}\n"
            f"- focus_pocs={reflector.get('focus_pocs') or []}\n"
            f"- reason={reflector.get('reason') or ''}\n"
            + ("- issues:\n" + "\n".join(issue_lines) + "\n" if issue_lines else "")
            + ("【重入安全补证策略】\n" + "\n".join(safety_lines) if safety_lines else "")
        ).strip()

    def _merge_recon_result(self, existing: Dict[str, Any], new_data: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(existing or {})
        merged["summary"] = new_data.get("summary") or existing.get("summary") or ""

        existing_ports = list(existing.get("open_ports") or [])
        new_ports = list(new_data.get("open_ports") or [])
        merged["open_ports"] = sorted({*existing_ports, *new_ports})

        def _service_signature(item: Any) -> str:
            if isinstance(item, dict):
                return json.dumps(item, ensure_ascii=False, sort_keys=True)
            return str(item)

        services = []
        seen_services = set()
        for item in list(existing.get("services") or []) + list(new_data.get("services") or []):
            sig = _service_signature(item)
            if sig in seen_services:
                continue
            seen_services.add(sig)
            services.append(item)
        merged["services"] = services

        topology = dict(existing.get("topology") or {})
        topology.update(new_data.get("topology") or {})
        merged["topology"] = topology

        adaptive_context = dict(existing.get("adaptive_context") or {})
        adaptive_context.update(new_data.get("adaptive_context") or {})
        merged["adaptive_context"] = adaptive_context
        merged["parse_error"] = new_data.get("parse_error")
        return merged

    def _merge_attack_plan_items(
        self,
        existing_items: List[Dict[str, Any]],
        new_items: List[Dict[str, Any]],
        target_steps: Optional[List[int]] = None,
        target_pocs: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        target_steps_set = set(target_steps or [])
        target_pocs_set = set(target_pocs or [])

        preserved: List[Dict[str, Any]] = []
        for item in existing_items or []:
            if target_steps_set or target_pocs_set:
                if item.get("step") in target_steps_set or item.get("poc_name") in target_pocs_set:
                    continue
            preserved.append(dict(item))

        combined = preserved + [dict(item) for item in (new_items or [])]
        deduped: List[Dict[str, Any]] = []
        seen = set()
        for item in combined:
            signature = (
                item.get("poc_name"),
                json.dumps(item.get("parameters") or {}, sort_keys=True, ensure_ascii=False),
            )
            if signature in seen:
                continue
            seen.add(signature)
            deduped.append(item)

        for index, item in enumerate(deduped, start=1):
            item["step"] = index
            item.setdefault("status", "pending")
        return deduped

    def _prepare_decision_reentry_targets(self, reflector: Dict[str, Any]) -> Dict[str, Any]:
        attack_plan = self.structured_results.get("attack_plan", {})
        existing_items = list(attack_plan.get("items") or [])
        focus_steps = list(reflector.get("focus_steps") or [])
        focus_pocs = list(reflector.get("focus_pocs") or [])

        self.structured_results.setdefault("attack_plan_archive", []).append(attack_plan)
        self.structured_results["decision_reentry"] = {
            "mode": reflector.get("rerun_mode") or "from_phase",
            "focus_steps": focus_steps,
            "focus_pocs": focus_pocs,
            "preserved_items": existing_items,
        }
        return {
            "focus_steps": focus_steps,
            "focus_pocs": focus_pocs,
            "existing_item_count": len(existing_items),
        }

    def hydrate_state(self, state: Dict[str, Any]):
        if self._has_user_supplied_attack_surface():
            self._clear_attack_surface_gate()
        self.current_logs = state.get("logs", []) or []
        self.phase_records = state.get("phase_records", []) or []
        self.findings = state.get("findings", []) or []
        self._finding_names = {item.get("name") for item in self.findings if item.get("name")}
        self.reflector_reentry_count = state.get("reflector_reentry_count", self.reflector_reentry_count)
        self.reflector_reentry_history = state.get("reflector_reentry_history", self.reflector_reentry_history) or []
        structured = state.get("structured", {}) or {}
        self.structured_results["recon"] = structured.get("recon", self.structured_results["recon"])
        self.structured_results["planner"] = structured.get("planner", self.structured_results["planner"])
        self.structured_results["attack_plan"] = structured.get("decision", structured.get("attack_plan", self.structured_results["attack_plan"]))
        self.structured_results["execution"] = structured.get("execute", structured.get("execution", self.structured_results["execution"]))
        self.structured_results["reflector"] = structured.get("reflector", self.structured_results["reflector"])
        self.structured_results["assessment"] = structured.get("assess", structured.get("assessment", self.structured_results["assessment"]))
        self.structured_results["supervisor"] = structured.get("supervisor", self.structured_results["supervisor"])
        gate = structured.get("attack_surface_gate")
        if not gate and isinstance(self.structured_results.get("recon"), dict):
            gate = self.structured_results["recon"].get("attack_surface_gate")
        if gate:
            self.structured_results["attack_surface_gate"] = gate
        recon_record = self._get_phase_record("recon")
        planner_record = self._get_phase_record("planner")
        decision_record = self._get_phase_record("decision")
        execute_record = self._get_phase_record("execute")
        reflector_record = self._get_phase_record("reflector")
        assess_record = self._get_phase_record("assess")
        self.recon_result = recon_record.get("raw_output") if recon_record else self.recon_result
        if planner_record and not self.structured_results.get("planner"):
            self.structured_results["planner"] = planner_record.get("structured_output") or {}
        self.attack_plan = decision_record.get("raw_output") if decision_record else self.attack_plan
        self.execution_results = execute_record.get("raw_output") if execute_record else self.execution_results
        if reflector_record and not self.structured_results.get("reflector"):
            self.structured_results["reflector"] = reflector_record.get("structured_output") or {}
        self.final_report = assess_record.get("raw_output") if assess_record else self.final_report
        self._refresh_supervisor_metrics()

    def _run_reflector(self) -> Tuple[str, Dict[str, Any]]:
        recon_data = self.structured_results.get("recon", {})
        attack_plan = self.structured_results.get("attack_plan", {})
        execution = self.structured_results.get("execution", {})
        supervisor = self.structured_results.get("supervisor", {})
        execution_items = execution.get("items") or []
        error_items = [item for item in execution_items if item.get("error")]
        vulnerable_items = [item for item in execution_items if item.get("vulnerable")]

        reflection_context = (
            f"目标IP: {self.target_ip}\n\n"
            f"侦察结果(JSON):\n{_safe_json_dumps(recon_data)}\n\n"
            f"任务编排(JSON):\n{_safe_json_dumps(self.structured_results.get('planner', {}))}\n\n"
            f"攻击计划(JSON):\n{_safe_json_dumps(attack_plan)}\n\n"
            f"执行结果(JSON):\n{_safe_json_dumps(execution)}\n\n"
            f"监督事件(JSON):\n{_safe_json_dumps(supervisor.get('events', []))}\n\n"
            f"监督调整(JSON):\n{_safe_json_dumps(supervisor.get('adjustments', []))}"
        )

        reflector_result, structured = self._call_agent_with_validation(
            phase="reflector",
            agent=self.reflector_agent,
            user_message=(
                "请审计本次自动化渗透测试流程。"
                "请根据执行成效、证据充分性、计划偏差和后续动作建议，严格输出 JSON 审计结果。"
                "如果需要补证、重跑或切换路径，请明确给出 next_action、next_phase 和 reentry_required。"
            ),
            context=reflection_context,
            normalizer=self._normalize_reflector_result,
            validator=self._validate_reflector_result,
            correction_hint=(
                "输出必须是一个合法 JSON 对象，必须包含 summary、execution_effective、"
                "evidence_sufficient、outcome_status、issues、next_action、next_phase、"
                "rerun_mode、focus_steps、focus_pocs、reentry_required、reason 字段。"
            ),
        )
        structured.update({
            "status": "success",
            "raw_summary": reflector_result,
            "error_count": len(error_items),
            "finding_count": len(vulnerable_items),
            "adjustments": supervisor.get("adjustments", []),
        })
        self.structured_results["reflector"] = structured
        return reflector_result, structured

    def _validate_recon_result(self, structured: Dict[str, Any]) -> Tuple[bool, str]:
        if structured.get("open_ports") or structured.get("services") or structured.get("topology"):
            return True, ""
        if structured.get("parse_error"):
            return False, f"侦察结果无法解析为结构化 JSON: {structured['parse_error']}"
        return False, "侦察结果缺少 open_ports/services/topology 等关键字段"

    def _validate_attack_plan(self, structured: Dict[str, Any]) -> Tuple[bool, str]:
        items = structured.get("items") or []
        if items:
            invalid = [item for item in items if not item.get("poc_name")]
            if invalid:
                return False, "攻击计划中存在缺少 poc_name 的项"
            return True, ""
        if structured.get("parse_error"):
            return False, f"攻击计划无法解析为 JSON: {structured['parse_error']}"
        return False, "攻击计划为空，未生成可执行步骤"

    def _validate_execution_result(self, structured: Dict[str, Any]) -> Tuple[bool, str]:
        if structured.get("parse_error"):
            return False, f"执行结果无法解析为 JSON: {structured['parse_error']}"
        return True, ""

    def _validate_reflector_result(self, structured: Dict[str, Any]) -> Tuple[bool, str]:
        if structured.get("parse_error"):
            return False, f"Reflector 输出无法解析为 JSON: {structured['parse_error']}"
        next_action = structured.get("next_action")
        if next_action not in {"continue", "retry", "branch", "stop", "escalate"}:
            return False, f"Reflector 返回了未知 next_action: {next_action}"
        next_phase = structured.get("next_phase") or ""
        if next_phase and next_phase not in PHASE_SEQUENCE:
            return False, f"Reflector 返回了未知 next_phase: {next_phase}"
        rerun_mode = structured.get("rerun_mode") or "from_phase"
        if rerun_mode not in {"targeted", "from_phase"}:
            return False, f"Reflector 返回了未知 rerun_mode: {rerun_mode}"
        if structured.get("reentry_required") and next_phase not in {"recon", "planner", "decision", "weaponize", "execute"}:
            return False, "Reflector 要求重入执行，但 next_phase 不是可回跳的执行阶段"
        if structured.get("reentry_required") and rerun_mode == "targeted" and next_phase != "execute":
            return False, "定向重跑当前仅支持 execute 阶段"
        return True, ""

    def _prepare_execute_reentry_targets(self, reflector: Dict[str, Any]) -> Dict[str, Any]:
        plan_items = self.structured_results.get("attack_plan", {}).get("items") or []
        execution_items = self.structured_results.get("execution", {}).get("items") or []
        focus_steps = set(reflector.get("focus_steps") or [])
        focus_pocs = set(reflector.get("focus_pocs") or [])
        targeted_steps: List[int] = []
        targeted_pocs: List[str] = []
        skipped_steps: List[int] = []

        latest_by_step: Dict[int, Dict[str, Any]] = {}
        latest_by_poc: Dict[str, Dict[str, Any]] = {}
        for item in execution_items:
            step = item.get("step")
            poc_name = item.get("poc_name")
            if isinstance(step, int):
                latest_by_step[step] = item
            if poc_name:
                latest_by_poc[poc_name] = item

        def should_target(item: Dict[str, Any]) -> bool:
            step = item.get("step")
            poc_name = item.get("poc_name")
            exec_item = latest_by_step.get(step) if isinstance(step, int) else None
            if exec_item is None and poc_name:
                exec_item = latest_by_poc.get(str(poc_name))
            if focus_steps or focus_pocs:
                return bool((step in focus_steps) or (poc_name in focus_pocs))
            if exec_item is None:
                return True
            if exec_item.get("status") in {"error", "blocked", "pending"} or exec_item.get("error"):
                return True
            if not reflector.get("evidence_sufficient") and not str(exec_item.get("evidence") or "").strip():
                return True
            if not reflector.get("execution_effective") and exec_item.get("status") == "completed":
                return True
            return False

        execution_archive = self.structured_results.setdefault("execution_archive", [])
        if self.structured_results.get("execution", {}).get("items"):
            execution_archive.append(self.structured_results.get("execution"))

        for item in plan_items:
            step = item.get("step")
            poc_name = item.get("poc_name")
            if should_target(item):
                item["status"] = "pending"
                item.pop("reason", None)
                if isinstance(step, int):
                    targeted_steps.append(step)
                if poc_name:
                    targeted_pocs.append(poc_name)
            else:
                item["status"] = "skipped_by_reflector_reentry"
                item["reason"] = "Reflector 指定本轮仅补证/重跑目标步骤，当前步骤暂不重复执行"
                if isinstance(step, int):
                    skipped_steps.append(step)

        self.structured_results["attack_plan"]["item_count"] = len(plan_items)
        self.attack_plan = _safe_json_dumps(self.structured_results["attack_plan"])
        self.structured_results["execution"] = {"items": [], "summary": "等待 Reflector 定向重跑", "parse_error": None, "item_count": 0}
        return {
            "targeted_steps": sorted(set(targeted_steps)),
            "targeted_pocs": sorted(set(targeted_pocs)),
            "skipped_steps": sorted(set(skipped_steps)),
        }

    def _maybe_resume_from_reflector(self) -> Optional[Dict[str, Any]]:
        reflector = self.structured_results.get("reflector", {}) or {}
        if not reflector.get("reentry_required"):
            return None

        next_action = reflector.get("next_action")
        next_phase = reflector.get("next_phase")
        if next_action not in {"retry", "branch"} or next_phase not in {"recon", "planner", "decision", "weaponize", "execute"}:
            return None

        if self.reflector_reentry_count >= REFLECTOR_MAX_REENTRY:
            message = (
                f"Reflector 已连续请求回跳 {self.reflector_reentry_count} 次，"
                "达到保护上限，停止自动重入并继续生成最终报告。"
            )
            reflector["reentry_required"] = False
            reflector["next_action"] = "escalate"
            reflector["reason"] = reflector.get("reason") or message
            reflector["reentry_suppressed"] = True
            self._record_supervisor_event("reflector_reentry_limit", message, severity="error", phase="reflector")
            return None

        self.reflector_reentry_count += 1
        reroute_reason = reflector.get("reason") or reflector.get("summary") or "Reflector 要求补证或调整路径"
        reroute_message = (
            f"Reflector 判定当前结果需要补证或未达预期，准备回跳到阶段 {next_phase} 重新执行。"
            f"原因: {reroute_reason}"
        )
        reroute_detail: Dict[str, Any] = {}
        if next_phase == "decision" and reflector.get("rerun_mode") == "targeted":
            reroute_detail = self._prepare_decision_reentry_targets(reflector)
            reroute_message += (
                f" 本次仅局部重规划 focus_steps={reroute_detail.get('focus_steps') or []}"
                f"，focus_pocs={reroute_detail.get('focus_pocs') or []}。"
            )
        if next_phase == "execute" and reflector.get("rerun_mode") == "targeted":
            reroute_detail = self._prepare_execute_reentry_targets(reflector)
            reroute_message += (
                f" 本次仅重跑步骤 {reroute_detail.get('targeted_steps') or []}"
                f"，跳过步骤 {reroute_detail.get('skipped_steps') or []}。"
            )
        self.reflector_reentry_history.append({
            "count": self.reflector_reentry_count,
            "next_phase": next_phase,
            "next_action": next_action,
            "reason": reroute_reason,
            "rerun_mode": reflector.get("rerun_mode") or "from_phase",
            "focus_steps": reflector.get("focus_steps") or [],
            "focus_pocs": reflector.get("focus_pocs") or [],
            "detail": reroute_detail,
            "timestamp": _utc_timestamp(),
        })
        self._record_supervisor_event("reflector_reroute", reroute_message, severity="warning", phase="reflector")
        self._record_supervisor_adjustment("reflector_reroute", reroute_message)
        self._add_log({"type": "warning", "message": f"[Reflector Agent] {reroute_message}"})
        return self.run_from_phase(next_phase)

    def _call_agent_with_validation(
        self,
        phase: str,
        agent: QwenAgent,
        user_message: str,
        context: str,
        normalizer,
        validator,
        correction_hint: str,
    ) -> Tuple[str, Dict[str, Any]]:
        max_attempts = PHASE_RETRY_LIMITS.get(phase, 1)
        current_message = user_message
        current_context = context
        last_result = ""
        last_structured: Dict[str, Any] = {}
        last_error = ""

        for attempt in range(1, max_attempts + 1):
            state = "running" if attempt == 1 else "retrying"
            self._upsert_phase_record(phase=phase, status=state, attempt=attempt)
            self._add_log({
                "type": "info",
                "message": f"[*] 阶段 {phase} 第 {attempt}/{max_attempts} 次执行",
            })

            last_result = agent.call(current_message, context=current_context)
            last_structured = normalizer(last_result)
            valid, reason = validator(last_structured)
            last_error = reason

            if valid:
                self._upsert_phase_record(
                    phase=phase,
                    status="done",
                    attempt=attempt,
                    raw_output=last_result,
                    structured_output=last_structured,
                )
                return last_result, last_structured

            self._add_log({
                "type": "warning",
                "message": f"[!] 阶段 {phase} 输出校验失败: {reason}",
            })
            self._upsert_phase_record(
                phase=phase,
                status="retrying" if attempt < max_attempts else "error",
                attempt=attempt,
                raw_output=last_result,
                structured_output=last_structured,
                error=reason,
            )
            current_context = (
                f"{context}\n\n"
                f"上一次输出内容:\n{last_result}\n\n"
                f"校验失败原因:\n{reason}\n\n"
                f"{correction_hint}"
            )
            current_message = (
                f"{user_message}\n\n"
                "请严格修正为可解析的结构化输出，不要解释，不要额外散文。"
            )

        return last_result, last_structured

    def _build_experiment_assessment_stub(self) -> str:
        """实验模式：不调用 Assessment LLM，仅输出结构化摘要供指标统计。"""
        execution = (self.structured_results.get("execution") or {}).get("items") or []
        vuln_count = len(self.findings)
        executed = len(execution)
        errors = sum(1 for item in execution if item.get("error"))
        open_ports = (self.structured_results.get("recon") or {}).get("open_ports") or []
        return (
            f"# 实验模式评估摘要（已跳过完整安全报告）\n\n"
            f"## 目标\n"
            f"- **{self.target_name}** (`{self.target_ip}`)\n\n"
            f"## 执行统计\n"
            f"- 侦察开放端口: {open_ports}\n"
            f"- 执行 PoC 数: {executed}（失败 {errors}）\n"
            f"- 检出漏洞: {vuln_count}\n\n"
            f"## 说明\n"
            f"`skip_assessment_report=true`：为缩短实验耗时，未调用 Assessment Agent 生成长文安全报告。"
            f"结构化结果见 `structured.execution` / `findings`。\n"
        )

    def _run_assessment_phase(self, context: str = "") -> str:
        gate = self.structured_results.get("attack_surface_gate")
        execution_items = (self.structured_results.get("execution") or {}).get("items") or []
        gate_blocks = bool(gate and gate.get("blocked") and not execution_items)
        if self._has_user_supplied_attack_surface():
            gate_blocks = False
        if gate_blocks and isinstance(gate, dict):
            report = self._build_minimal_no_surface_report(gate)
            self.structured_results["assessment"] = {
                "report_markdown": report,
                "finding_count": 0,
                "attack_surface_gate": gate,
                "skipped_full_report": True,
            }
            return report

        if self.skip_assessment_report:
            report = self._build_experiment_assessment_stub()
            self.structured_results["assessment"] = {
                "report_markdown": report,
                "finding_count": len(self.findings),
                "skipped_full_report": True,
                "skip_reason": "experiment_mode",
            }
            self._add_log({
                "type": "info",
                "message": "[Orchestrator] 已跳过 Assessment Agent 长文安全报告（实验模式）。",
            })
            return report

        assessment_input = self._build_assessment_call(context=context)
        report = self.assessment_agent.call(
            assessment_input["prompt"],
            context=assessment_input["context"],
        )
        self.structured_results["assessment"] = {
            "report_markdown": report,
            "finding_count": len(self.findings),
            "skipped_full_report": False,
        }
        return report

    def _build_assessment_call(self, context: str = "") -> Dict[str, str]:
        """为评估 Agent 统一构造报告元数据，禁止模型自行编造日期或团队。"""
        return build_assessment_call(
            target_ip=self.target_ip,
            target_name=self.target_name,
            context=context,
        )

    def _add_log(self, entry: Any):
        """添加一条日志到缓冲区"""
        if isinstance(entry, dict):
            # 补全时间戳（如果缺失）
            if "timestamp" not in entry:
                entry["timestamp"] = time.strftime("%H:%M:%S")
            self.current_logs.append(entry)
            
            # 自动捕获漏洞发现：仅在日志中能可靠解析出 PoC 文件名时才补录 finding，
            # 避免生成“未知漏洞”这类伪结果污染前端展示。
            msg = entry.get("message", "")
            if "[Executor] PoC 执行完毕: 发现漏洞!" in msg:
                match = re.search(r'\(文件名:\s*([^)]+)\)', msg)
                if match:
                    poc_name = match.group(1).strip()
                else:
                    # 兼容性回滚：优先回溯最近的执行步骤日志，再尝试回溯 run_poc 调用日志
                    poc_name = ""
                    for prev in reversed(self.current_logs[:-1]):
                        step_match = re.search(r'\[Executor-Step\]\s+开始执行步骤\s+\d+:\s+(.+)$', prev.get("message", ""))
                        if step_match:
                            poc_name = step_match.group(1).strip()
                            break
                        if "调用工具: run_poc" in prev.get("message", ""):
                            n_match = re.search(r'poc_name":\s*"([^"]+)"', prev.get("message", ""))
                            if n_match:
                                poc_name = n_match.group(1)
                            break
                if poc_name:
                    self._register_finding(poc_name, source="executor_log")
        else:
            self.current_logs.append({
                "timestamp": time.strftime("%H:%M:%S"),
                "type": "info",
                "message": str(entry)
            })

    def _load_mcp_tools(self) -> List[dict]:
        """从 MCP Server 加载工具列表"""
        try:
            resp = requests.get(f"{MCP_SERVER}/mcp/tools", timeout=5)
            if resp.ok:
                tools = resp.json().get("tools", [])
                logger.info(f"[Orchestrator] 成功加载 {len(tools)} 个 MCP 工具")
                return tools
        except Exception as e:
            logger.warning(f"[Orchestrator] 无法连接 MCP Server ({e})，使用内置工具列表")

        # 降级：返回内置工具定义
        from mcp_server import MCP_TOOLS
        return MCP_TOOLS

    def run_full_assessment(self, reset_reentry_state: bool = True) -> Dict[str, Any]:
        """
        执行完整的 7-Agent 协作渗透测试评估
        返回包含所有阶段结果的综合报告字典
        """
        logger.info(f"[Orchestrator] ===== 开始自主协作渗透测试: {self.target_name} ({self.target_ip}) =====")
        self.phase_records = []
        self.execution_trace = []
        self.structured_results["supervisor"] = {"events": [], "metrics": {}, "adjustments": []}
        if reset_reentry_state:
            self.reflector_reentry_count = 0
            self.reflector_reentry_history = []
            self.structured_results.pop("decision_reentry", None)
        for phase_name in PHASE_SEQUENCE:
            self._upsert_phase_record(phase=phase_name, status="pending")

        # 将可用资源格式化为提示词上下文
        _params_desc_parts = [f"target_ip={self.target_ip}"]
        if "can_interface" in self.available_params:
            _params_desc_parts.append(f"can_interface={self.available_params['can_interface']}")
        else:
            _params_desc_parts.append("can_interface=未提供（跳过所有 CAN/ISO-TP 相关 PoC）")
        if "bluetooth_mac" in self.available_params:
            _params_desc_parts.append(f"bluetooth_mac={self.available_params['bluetooth_mac']}")
        else:
            _params_desc_parts.append("bluetooth_mac=未提供（跳过所有蓝牙/BLE 相关 PoC）")
        if "wifi_interface" in self.available_params:
            _params_desc_parts.append(f"wifi_interface={self.available_params['wifi_interface']}")
        else:
            _params_desc_parts.append("wifi_interface=未提供（跳过所有无线嗅探相关 PoC）")
        if self._usb_adb_resources_ready():
            if self.available_params.get("expected_usb_serial"):
                _params_desc_parts.append(
                    f"expected_usb_serial={self.available_params['expected_usb_serial']}（本机 USB ADB）"
                )
            else:
                _params_desc_parts.append(
                    f"local_usb_adb_attached=true（唯一 USB 设备）"
                )
        else:
            _params_desc_parts.append(
                self.available_params.get("usb_adb_block_reason") or "本机 USB ADB 未满足「仅 1 台」策略"
            )
        _available_params_ctx = "【可用资源】\n" + "\n".join(f"  - {p}" for p in _params_desc_parts)
        reflector_focus_ctx = self._build_reflector_focus_context()

        # ── Phase 1/7: 侦察（增强扫描 + Global 种子 + LLM 补充）──
        logger.info("[Orchestrator] Phase 1/7: 侦察 Agent 开始执行...")
        bootstrap_recon = self._bootstrap_recon()
        if bootstrap_recon.get("open_ports"):
            self.structured_results["recon"] = bootstrap_recon
            self._add_log({
                "type": "success",
                "message": (
                    f"[Orchestrator] 侦察基线已就绪：开放端口 {bootstrap_recon.get('open_ports')} "
                    f"（来源: {', '.join(bootstrap_recon.get('recon_sources') or [])}）"
                ),
            })
        previous_recon = dict(self.structured_results.get("recon") or {})
        recon_user_message = (
            f"对目标 {self.target_ip}（{self.target_name}）执行完整侦察。"
            f"使用 scan_ports（candidate_ports 已配置）发现开放服务，使用 get_topology 建立网络拓扑图，"
            f"使用 get_adaptive_context 获取目标服务指纹和认证机制。"
            f"输出 JSON 格式的侦察摘要；勿丢弃已有开放端口线索。"
        )
        if reflector_focus_ctx and (self.structured_results.get("reflector", {}) or {}).get("next_phase") == "recon":
            recon_user_message = (
                f"对目标 {self.target_ip}（{self.target_name}）执行补充侦察。"
                "请优先围绕 Reflector 指出的证据缺口、覆盖缺口或异常点补充信息，"
                "只扩展必要的侦察内容，并输出 JSON 格式的侦察摘要。"
            )
        self.recon_result, recon_structured = self._call_agent_with_validation(
            phase="recon",
            agent=self.recon_agent,
            user_message=recon_user_message,
            context=_available_params_ctx + (f"\n\n{reflector_focus_ctx}" if reflector_focus_ctx else ""),
            normalizer=self._normalize_recon_result,
            validator=self._validate_recon_result,
            correction_hint=(
                "输出必须是一个合法的 JSON 对象。格式示例：\n"
                "{\n"
                "  \"summary\": \"侦察摘要...\",\n"
                "  \"open_ports\": [22, 80],\n"
                "  \"services\": [\"ssh\", \"http\"],\n"
                "  \"topology\": { \"nodes\": [...] },\n"
                "  \"adaptive_context\": { ... }\n"
                "}"
            ),
        )
        if reflector_focus_ctx and previous_recon:
            recon_structured = self._merge_recon_result(previous_recon, recon_structured)
        elif previous_recon:
            from agent_recon_bootstrap import merge_recon_results
            recon_structured = merge_recon_results(previous_recon, recon_structured)
        self.structured_results["recon"] = recon_structured
        self._require_phase_success("recon")
        self._merge_agent_supervisor_events(self.recon_agent, "recon")
        logger.info(f"[Orchestrator] Phase 1 完成:\n{self.recon_result[:300]}...")

        gate = self._apply_attack_surface_gate(recon_structured)
        if gate:
            minimal_report = self._build_minimal_no_surface_report(gate)
            self.structured_results["planner"] = {
                "strategy_summary": "无可验证攻击面，跳过规划阶段。",
                "steps": [],
                "guardrails": ["insufficient_attack_surface"],
                "attack_surface_gate": gate,
            }
            self.structured_results["attack_plan"] = {
                "items": [],
                "summary": "无可验证攻击面，未生成 PoC 执行计划。",
                "parse_error": None,
                "item_count": 0,
                "attack_surface_gate": gate,
            }
            self.structured_results["execution"] = {
                "items": [],
                "summary": "攻击面不足，未执行 PoC。",
                "parse_error": None,
                "item_count": 0,
                "attack_surface_gate": gate,
            }
            self.structured_results["reflector"] = {
                "summary": "攻击面 Gate 已阻断无目标执行。",
                "execution_effective": False,
                "evidence_sufficient": False,
                "outcome_status": "insufficient_attack_surface",
                "next_action": "stop",
                "next_phase": "assess",
                "reentry_required": False,
                "reason": gate["reason"],
            }
            self.final_report = minimal_report
            self.structured_results["assessment"] = {
                "report_markdown": minimal_report,
                "finding_count": 0,
                "attack_surface_gate": gate,
            }
            for skipped_phase in ("planner", "decision", "weaponize", "execute", "reflector"):
                self._record_phase(skipped_phase, "skipped", gate["reason"], {"attack_surface_gate": gate})
            self._record_phase("assess", "done", minimal_report, self.structured_results["assessment"])
            self._refresh_supervisor_metrics()
            self._refresh_llm_usage()
            duration = round(time.time() - self.start_time, 1)
            return {
                "target_ip": self.target_ip,
                "target_name": self.target_name,
                "duration_seconds": duration,
                "logs": self.current_logs,
                "phase_records": self.phase_records,
                "findings": self.findings,
                "reflector_reentry_count": self.reflector_reentry_count,
                "reflector_reentry_history": self.reflector_reentry_history,
                "manual_review_wait_seconds": round(self.manual_review_wait_seconds, 3),
                "llm_usage": self.structured_results.get("llm_usage", {}),
                "structured": self.structured_results,
                "phases": {
                    "recon": self.recon_result,
                    "attack_plan": self.attack_plan,
                    "execution": self.execution_results,
                    "assessment_report": self.final_report,
                },
            }

        # ── Phase 2/7: 规划 Agent ──
        logger.info("[Orchestrator] Phase 2/7: 规划 Agent 开始生成任务编排...")
        self._add_log({"type": "info", "message": "[Orchestrator] Phase 2: 规划 Agent 正在基于攻击面生成任务编排..."})
        planner_result, planner_structured = self._run_planner()
        self.structured_results["planner"] = planner_structured
        self._upsert_phase_record(
            phase="planner",
            status="done",
            attempt=1,
            raw_output=planner_result,
            structured_output=planner_structured
        )
        self._add_log({"type": "success", "message": f"[Planner Agent] 任务编排生成完成，包含 {len(planner_structured.get('steps', []))} 个关键步骤。"})
        logger.info(f"[Orchestrator] Phase 2 完成:\n{planner_result[:200]}...")

        # ── Phase 3/7: 决策 Agent ──
        logger.info("[Orchestrator] Phase 3/7: 决策 Agent 开始规划攻击路径...")
        recon_data = self.structured_results.get("recon", {})
        open_ports = recon_data.get("open_ports") or []
        global_vuln_pocs = recon_data.get("global_vulnerable_pocs") or []
        poc_inventory = self._build_decision_poc_context(recon_data)
        decision_reentry = self.structured_results.get("decision_reentry", {}) or {}
        decision_user_message = (
            f"基于侦察结果和以下可用资源，从【可用 PoC 脚本库】中挑选合适的脚本执行。"
            f"针对 {self.target_ip} 的开放端口 {open_ports} 规划渗透路径。"
            f"输出 JSON 攻击计划，每项包含精确的 poc_name (如 'network/03_SSH_Service.py')。"
        )
        if global_vuln_pocs:
            decision_user_message += (
                f" Global 扫描已标记 {len(global_vuln_pocs)} 个高风险 PoC，"
                "请优先纳入攻击计划进行定向复验。"
            )
        if decision_reentry.get("mode") == "targeted":
            decision_user_message = (
                f"请针对目标 {self.target_ip} 执行局部重规划。"
                "仅围绕 Reflector 指出的缺口、异常步骤或目标 PoC 补充/替换必要攻击步骤，"
                "避免重复输出已经合理且无需调整的既有路径。"
            )
        
        self.attack_plan, decision_structured = self._call_agent_with_validation(
            phase="decision",
            agent=self.decision_agent,
            user_message=decision_user_message,
            context=(
                f"{_available_params_ctx}\n\n"
                f"{poc_inventory}\n\n"
                f"侦察结果(JSON):\n{_safe_json_dumps(self.structured_results['recon'])}\n\n"
                f"Global已检出PoC(优先复验):\n{_safe_json_dumps(global_vuln_pocs)}\n\n"
                f"任务编排(JSON):\n{_safe_json_dumps(self.structured_results['planner'])}"
                + (f"\n\n{reflector_focus_ctx}" if reflector_focus_ctx else "")
                + (
                    f"\n\n既有攻击计划(JSON):\n{_safe_json_dumps(decision_reentry.get('preserved_items') or [])}"
                    if decision_reentry.get("mode") == "targeted" else ""
                )
            ),
            normalizer=self._normalize_attack_plan,
            validator=self._validate_attack_plan,
            correction_hint=(
                "输出必须是包含 attack_plan 字段的 JSON 对象。格式示例：\n"
                "{\n"
                "  \"attack_plan\": [\n"
                "    {\"poc_name\": \"network/ssh_scan.py\", \"parameters\": {\"target_ip\":\"1.1.1.1\"}, \"strategy\":\"...\", \"reason\":\"...\"}\n"
                "  ]\n"
                "}"
            ),
        )
        if decision_reentry.get("mode") == "targeted":
            merged_items = self._merge_attack_plan_items(
                decision_reentry.get("preserved_items") or [],
                decision_structured.get("items") or [],
                decision_reentry.get("focus_steps") or [],
                decision_reentry.get("focus_pocs") or [],
            )
            decision_structured["items"] = merged_items
            decision_structured["item_count"] = len(merged_items)
            decision_structured["summary"] = self.attack_plan
            self.attack_plan = _safe_json_dumps(decision_structured)
            self.structured_results.pop("decision_reentry", None)
        decision_structured = self._ensure_usb_adb_plan_item(decision_structured)
        self.attack_plan = _safe_json_dumps(decision_structured)
        self.structured_results["attack_plan"] = decision_structured
        self._require_phase_success("decision")
        
        # Self-Correction: If recon found ports but decision agent scheduled nothing, retry once
        if open_ports and not self.structured_results["attack_plan"].get("items"):
            self._add_log({"type": "warning", "message": "[Strategy] 警告: 侦察发现了端口但决策 Agent 未生成攻击步骤。触发二次校准重试..."})
            self._record_supervisor_event("strategy_gap", "决策 Agent 未能针对发现的端口生成路径，正在强制重试。", phase="decision")
            
            self.attack_plan, self.structured_results["attack_plan"] = self._call_agent_with_validation(
                phase="decision",
                agent=self.decision_agent,
                user_message=(
                    f"请务必针对以下开放端口生成至少一个攻击步骤: {open_ports}。"
                    f"必须从【可用 PoC 脚本库】中选择对应的脚本。"
                ),
                context=(
                    f"{_available_params_ctx}\n\n"
                    f"{poc_inventory}\n\n"
                    f"侦察结果(JSON):\n{_safe_json_dumps(recon_data)}"
                ),
                normalizer=self._normalize_attack_plan,
                validator=self._validate_attack_plan,
                correction_hint="必须从提供的 PoC 元数据表与端口映射中选择精确的 poc_name 路径。",
            )
            self.structured_results["attack_plan"] = self._ensure_usb_adb_plan_item(
                self.structured_results["attack_plan"]
            )
            self.attack_plan = _safe_json_dumps(self.structured_results["attack_plan"])

        self._apply_heuristic_attack_plan_if_empty(recon_data)
        self._append_baseline_replay_plan_items()
        self._merge_agent_supervisor_events(self.decision_agent, "decision")
        self._supervise_attack_plan()
        self._sort_attack_plan_recon_first()
        self.execution_trace = list(self.structured_results["attack_plan"].get("items", []))
        logger.info(f"[Orchestrator] Phase 3 完成:\n{self.attack_plan[:300]}...")

        # ── Phase 4/7: 武器化 Agent ──
        if any(_is_dynamic_probe_name(item.get("poc_name")) for item in self.structured_results["attack_plan"].get("items", [])):
            logger.info("[Orchestrator] Phase 4/7: 触发 Weaponize Agent 介入...")
            self._add_log({"type": "warning", "message": "[Orchestrator] 检测到未知服务，Weaponize Agent 介入生成协议感知型动态探测脚本..."})
            weaponize_result = self.weaponize_agent.call(
                f"针对目标 {self.target_ip} 的未知服务，生成可直接在当前环境下运行的 Python 协议感知型动态探测代码。",
                context=(
                    f"侦察结果(JSON):\n{_safe_json_dumps(self.structured_results['recon'])}\n\n"
                    f"攻击计划(JSON):\n{_safe_json_dumps(self.structured_results['attack_plan'])}"
                )
            )
            code_match = re.search(r'```python\s*(.*?)\s*```', weaponize_result, re.DOTALL)
            if code_match:
                sandbox_dir = "/tmp/autosec_sandbox"
                os.makedirs(sandbox_dir, exist_ok=True)
                timestamp = int(time.time())
                sandbox_file = os.path.join(sandbox_dir, f"15_Dynamic_Unknown_Service_Probe_{timestamp}.py")
                with open(sandbox_file, "w") as f:
                    f.write(_wrap_code_as_plugin(code_match.group(1)))
                for item in self.structured_results["attack_plan"].get("items", []):
                    if _is_dynamic_probe_name(item.get("poc_name")):
                        item["poc_name"] = sandbox_file
                        item["status"] = "weaponized"
                self.attack_plan = _safe_json_dumps(self.structured_results["attack_plan"])
                self._add_log({"type": "success", "message": f"[Weaponize Agent] 成功投递并沙箱化探测脚本: {sandbox_file}"})
                self._record_phase("weaponize", "done", weaponize_result, {"weaponized": True})
            else:
                self._record_phase("weaponize", "error", weaponize_result, {"weaponized": False}, "Generation failed")
            self._require_phase_success("weaponize")
        else:
            self._record_phase("weaponize", "skipped", "No dynamic unknown service probe required", {"weaponized": False})

        # ── Phase 5/7: 执行 Agent ──
        logger.info("[Orchestrator] Phase 5/7: 执行 Agent 开始逐步执行渗透测试...")
        self._add_log({"type": "info", "message": "[Orchestrator] Phase 5: 执行 Agent 启动，正在逐项验证攻击路径..."})
        self._upsert_phase_record(phase="execute", status="running", attempt=1)
        self.execution_results, self.structured_results["execution"] = self._execute_plan_stepwise()
        valid, reason = self._validate_execution_result(self.structured_results["execution"])
        if not valid:
            self._record_phase("execute", "error", self.execution_results, self.structured_results["execution"], reason)
            self._add_log({"type": "error", "message": f"[Executor Agent] 执行阶段发生异常: {reason}"})
            self._require_phase_success("execute")
        else:
            self._record_phase("execute", "done", self.execution_results, self.structured_results["execution"])
            self._add_log({"type": "success", "message": f"[Executor Agent] 执行阶段完成，发现了 {len(self.findings)} 个确认的漏洞点。"})
        self._supervise_execution_outcome()
        logger.info(f"[Orchestrator] Phase 5 完成:\n{self.execution_results[:300]}...")

        # ── Phase 6/7: 反思 Agent ──
        logger.info("[Orchestrator] Phase 6/7: 反思 Agent 启动评估...")
        self._add_log({"type": "info", "message": "[Orchestrator] Phase 6: 反思 Agent 正在进行执行偏差与安全性审计..."})
        reflector_result, reflector_structured = self._run_reflector()
        self._add_log({"type": "success", "message": "[Reflector Agent] 深度审计完成：审计意见已整合至报告。"})
        
        self._upsert_phase_record(
            phase="reflector",
            status="done",
            attempt=1,
            raw_output=reflector_result,
            structured_output=reflector_structured
        )
        logger.info(f"[Orchestrator] Phase 6 结论: {reflector_result}")
        rerouted = self._maybe_resume_from_reflector()
        if rerouted is not None:
            return rerouted

        # ── Phase 7/7: 评估（实验可跳过 LLM 长文报告）──
        if self.skip_assessment_report:
            logger.info("[Orchestrator] Phase 7/7: 实验模式，跳过 Assessment Agent 长文报告...")
        else:
            logger.info("[Orchestrator] Phase 7/7: 评估 Agent 生成安全报告...")
        assess_context = (
            f"侦察结果:\n{self.recon_result}\n\n"
            f"攻击计划(JSON):\n{_safe_json_dumps(self.structured_results['attack_plan'])}\n\n"
            f"执行结果(JSON):\n{_safe_json_dumps(self.structured_results['execution'])}\n\n"
            f"漏洞发现(JSON):\n{_safe_json_dumps(self.findings)}\n\n"
            f"反思审计(JSON):\n{_safe_json_dumps(self.structured_results.get('reflector', {}))}"
        )
        self.final_report = self._run_assessment_phase(context=assess_context)
        self._record_phase("assess", "done", self.final_report, self.structured_results["assessment"])
        logger.info("[Orchestrator] Phase 7 完成。")
        self._refresh_supervisor_metrics()
        self._refresh_llm_usage()

        duration = round(time.time() - self.start_time, 1)
        logger.info(f"[Orchestrator] ===== 自主渗透测试完成，总耗时 {duration}s =====")

        return {
            "target_ip": self.target_ip,
            "target_name": self.target_name,
            "duration_seconds": duration,
            "logs": self.current_logs,
            "phase_records": self.phase_records,
            "findings": self.findings,
            "reflector_reentry_count": self.reflector_reentry_count,
            "reflector_reentry_history": self.reflector_reentry_history,
            "manual_review_wait_seconds": round(self.manual_review_wait_seconds, 3),
            "llm_usage": self.structured_results.get("llm_usage", {}),
            "structured": self.structured_results,
            "phases": {
                "recon": self.recon_result,
                "attack_plan": self.attack_plan,
                "execution": self.execution_results,
                "assessment_report": self.final_report,
            }
        }

    def run_from_phase(self, start_phase: str) -> Dict[str, Any]:
        if start_phase not in PHASE_SEQUENCE:
            raise ValueError(f"Unknown start phase: {start_phase}")

        logger.info(f"[Orchestrator] ===== 从阶段 {start_phase} 恢复执行: {self.target_name} ({self.target_ip}) =====")
        available_params_ctx = self._build_available_params_context()
        reflector_focus_ctx = self._build_reflector_focus_context()
        start_index = PHASE_SEQUENCE.index(start_phase)

        if start_index <= PHASE_SEQUENCE.index("recon"):
            return self.run_full_assessment(reset_reentry_state=False)

        if start_index <= PHASE_SEQUENCE.index("planner"):
             # For planner, we just run it directly as it's a rule/prompt based orchestration
             self._upsert_phase_record(phase="planner", status="running", attempt=1)
             planner_result, planner_structured = self._run_planner()
             self.structured_results["planner"] = planner_structured
             self._upsert_phase_record(phase="planner", status="done", attempt=1, raw_output=planner_result, structured_output=planner_structured)

        if start_index <= PHASE_SEQUENCE.index("decision"):
             if not self.structured_results.get("planner", {}).get("steps"):
                 self._run_planner()
             decision_reentry = self.structured_results.get("decision_reentry", {}) or {}
             decision_user_message = (
                 f"基于侦察结果和以下可用资源，规划针对 {self.target_ip} 的渗透测试计划。"
                 f"严格按照【可用资源】中的参数过滤 PoC：缺少 bluetooth_mac 则不选择蓝牙 PoC，"
                 f"缺少 can_interface 则不选择 CAN 总线 PoC，缺少 wifi_interface 则不选择无线嗅探 PoC，"
                 f"本机须恰好 1 台 USB ADB 设备才执行 network/01_USB_ADB_Debug.py。"
                 f"输出有序的 JSON 攻击计划，每项包含 poc_name 和 parameters 字段（parameters 中包含实际参数值）。"
             )
             if decision_reentry.get("mode") == "targeted":
                 decision_user_message = (
                     f"请针对目标 {self.target_ip} 执行局部重规划。"
                     "仅围绕 Reflector 指出的缺口、异常步骤或目标 PoC 补充/替换必要攻击步骤，"
                     "避免重复输出已经合理且无需调整的既有路径。"
                 )
             resume_recon = self.structured_results.get("recon", {})
             resume_poc_ctx = self._build_decision_poc_context(resume_recon)
             global_vuln_resume = resume_recon.get("global_vulnerable_pocs") or []
             self.attack_plan, decision_structured = self._call_agent_with_validation(
                 phase="decision",
                 agent=self.decision_agent,
                 user_message=decision_user_message,
                 context=(
                     f"{available_params_ctx}\n\n"
                     f"{resume_poc_ctx}\n\n"
                     f"Global已检出PoC(优先复验):\n{_safe_json_dumps(global_vuln_resume)}\n\n"
                     f"侦察结果(JSON):\n{_safe_json_dumps(resume_recon)}\n\n"
                     f"任务编排(JSON):\n{_safe_json_dumps(self.structured_results['planner'])}"
                     + (f"\n\n{reflector_focus_ctx}" if reflector_focus_ctx else "")
                     + (
                         f"\n\n既有攻击计划(JSON):\n{_safe_json_dumps(decision_reentry.get('preserved_items') or [])}"
                         if decision_reentry.get("mode") == "targeted" else ""
                     )
                 ),
                 normalizer=self._normalize_attack_plan,
                 validator=self._validate_attack_plan,
                 correction_hint="输出必须是 JSON 数组或包含 items/attack_plan 字段产生的结果。每个步骤必须包含 poc_name、parameters、strategy、reason。",
             )
             if decision_reentry.get("mode") == "targeted":
                 merged_items = self._merge_attack_plan_items(
                     decision_reentry.get("preserved_items") or [],
                     decision_structured.get("items") or [],
                     decision_reentry.get("focus_steps") or [],
                     decision_reentry.get("focus_pocs") or [],
                 )
                 decision_structured["items"] = merged_items
                 decision_structured["item_count"] = len(merged_items)
                 decision_structured["summary"] = self.attack_plan
                 self.attack_plan = _safe_json_dumps(decision_structured)
                 self.structured_results.pop("decision_reentry", None)
             decision_structured = self._ensure_usb_adb_plan_item(decision_structured)
             self.attack_plan = _safe_json_dumps(decision_structured)
             self.structured_results["attack_plan"] = decision_structured
             self._require_phase_success("decision")
             self._merge_agent_supervisor_events(self.decision_agent, "decision")
             self._supervise_attack_plan()
             self._apply_heuristic_attack_plan_if_empty(self.structured_results.get("recon", {}))
             self._append_baseline_replay_plan_items()
             self._sort_attack_plan_recon_first()

        if any(_is_dynamic_probe_name(item.get("poc_name")) for item in self.structured_results["attack_plan"].get("items", [])):
            logger.info("[Orchestrator] 恢复执行时检测到 dynamic_unknown_service_probe，重新触发 Weaponize Agent...")
            weaponize_result = self.weaponize_agent.call(
                f"针对目标 {self.target_ip} 的未知服务，生成可直接在当前环境下运行的 Python 协议感知型动态探测代码。",
                context=(
                    f"侦察结果(JSON):\n{_safe_json_dumps(self.structured_results['recon'])}\n\n"
                    f"攻击计划(JSON):\n{_safe_json_dumps(self.structured_results['attack_plan'])}"
                )
            )
            code_match = re.search(r'```python\s*(.*?)\s*```', weaponize_result, re.DOTALL)
            if code_match:
                sandbox_file = os.path.join(os.path.dirname(__file__), "pocs", DYNAMIC_PROBE_FILENAME)
                with open(sandbox_file, "w") as f:
                    f.write(_wrap_code_as_plugin(code_match.group(1)))
                for item in self.structured_results["attack_plan"]["items"]:
                    if _is_dynamic_probe_name(item.get("poc_name")):
                        item["poc_name"] = DYNAMIC_PROBE_FILENAME
                        item["status"] = "weaponized"
                self.attack_plan = _safe_json_dumps(self.structured_results["attack_plan"])
                self._record_phase("weaponize", "done", weaponize_result, {"weaponized": True})
            else:
                self._record_phase("weaponize", "error", weaponize_result, {"weaponized": False}, "dynamic unknown service probe generation failed")
                self._require_phase_success("weaponize")
        elif not self._get_phase_record("weaponize"):
            self._record_phase("weaponize", "skipped", "", {"weaponized": False})

        if start_index <= PHASE_SEQUENCE.index("execute"):
            existing_error_items = [
                item for item in (self.structured_results.get("execution", {}).get("items") or [])
                if item.get("error")
            ]
            if existing_error_items:
                self._prune_attack_plan_after_failures(existing_error_items)
            self._upsert_phase_record(phase="execute", status="running", attempt=1)
            self.execution_results, self.structured_results["execution"] = self._execute_plan_stepwise()
            valid, reason = self._validate_execution_result(self.structured_results["execution"])
            if not valid:
                self._record_phase("execute", "error", self.execution_results, self.structured_results["execution"], reason)
                self._require_phase_success("execute")
            else:
                self._record_phase("execute", "done", self.execution_results, self.structured_results["execution"])
            self._supervise_execution_outcome()

        if start_index <= PHASE_SEQUENCE.index("reflector"):
            reflector_result, reflector_structured = self._run_reflector()
            self._record_phase("reflector", "done", reflector_result, reflector_structured)
            rerouted = self._maybe_resume_from_reflector()
            if rerouted is not None:
                return rerouted

        assess_context = (
            f"侦察结果:\n{self.recon_result}\n\n"
            f"攻击计划(JSON):\n{_safe_json_dumps(self.structured_results['attack_plan'])}\n\n"
            f"执行结果(JSON):\n{_safe_json_dumps(self.structured_results['execution'])}\n\n"
            f"漏洞发现(JSON):\n{_safe_json_dumps(self.findings)}\n\n"
            f"反思审计(JSON):\n{_safe_json_dumps(self.structured_results.get('reflector', {}))}"
        )
        self.final_report = self._run_assessment_phase(context=assess_context)
        self._record_phase("assess", "done", self.final_report, self.structured_results["assessment"])
        self._refresh_supervisor_metrics()
        self._refresh_llm_usage()

        duration = round(time.time() - self.start_time, 1)
        return {
            "target_ip": self.target_ip,
            "target_name": self.target_name,
            "duration_seconds": duration,
            "logs": self.current_logs,
            "phase_records": self.phase_records,
            "findings": self.findings,
            "reflector_reentry_count": self.reflector_reentry_count,
            "reflector_reentry_history": self.reflector_reentry_history,
            "manual_review_wait_seconds": round(self.manual_review_wait_seconds, 3),
            "llm_usage": self.structured_results.get("llm_usage", {}),
            "structured": self.structured_results,
            "phases": {
                "recon": self.recon_result,
                "attack_plan": self.attack_plan,
                "execution": self.execution_results,
                "assessment_report": self.final_report,
            }
        }

    def run_phase(self, phase: str, context: str = "") -> Dict[str, Any]:
        """单独执行某一 Phase（供 API 调用）"""
        self.current_logs = []
        self._upsert_phase_record(phase=phase, status="pending")
        PHASE_NAMES = {
            "recon": "侦察 (Reconnaissance)",
            "planner": "任务编排 (Mission Planning)",
            "decision": "关键决策 (Critical Decision)",
            "weaponize": "动态探测生成 (Weaponization)",
            "execute": "漏洞利用 (Exploitation)",
            "reflector": "自适应反思 (Adaptive Reflection)",
            "assess": "风险评估 (Risk Assessment)"
        }
        friendly_name = PHASE_NAMES.get(phase, phase)
        self._add_log({"type": "info", "message": f"[*] 开始执行阶段: {friendly_name}"})
        
        result = ""
        structured: Dict[str, Any] = {}
        if phase == "recon":
            result, structured = self._call_agent_with_validation(
                phase="recon",
                agent=self.recon_agent,
                user_message=f"对目标 {self.target_ip} 执行侦察。使用 scan_ports + get_topology。",
                context=context,
                normalizer=self._normalize_recon_result,
                validator=self._validate_recon_result,
                correction_hint="输出必须是包含 summary、open_ports、services、topology 的 JSON 对象。",
            )
            self._require_phase_success("recon")
            self._merge_agent_supervisor_events(self.recon_agent, "recon")
            self.structured_results["recon"] = structured
            self.recon_result = result
            self._apply_attack_surface_gate(structured)
        elif phase == "planner":
            self._upsert_phase_record(phase="planner", status="running", attempt=1)
            planner_result, structured = self._run_planner()
            self._upsert_phase_record(phase="planner", status="done", attempt=1, raw_output=planner_result, structured_output=structured)
            result = planner_result
        elif phase == "decision":
            if self.structured_results.get("recon", {}).get("open_ports") and not self.structured_results.get("planner", {}).get("steps"):
                self._run_planner()
            poc_inventory = self._build_decision_poc_context(self.structured_results.get("recon", {}))
            result, structured = self._call_agent_with_validation(
                phase="decision",
                agent=self.decision_agent,
                user_message=f"从【可用 PoC 脚本库】中挑选合适的脚本针对 {self.target_ip} 进行测试。",
                context=(
                    f"{context}\n\n{poc_inventory}\n\n执行纲要(JSON):\n{_safe_json_dumps(self.structured_results['planner'])}"
                    if self.structured_results.get("planner", {}).get("steps")
                    else f"{context}\n\n{poc_inventory}"
                ),
                normalizer=self._normalize_attack_plan,
                validator=self._validate_attack_plan,
                correction_hint="必须从提供的文件列表中选择精确的 poc_name 路径。",
            )
            self._require_phase_success("decision")
            self._merge_agent_supervisor_events(self.decision_agent, "decision")
            structured = self._ensure_usb_adb_plan_item(structured)
            self.structured_results["attack_plan"] = structured
            self._supervise_attack_plan()
            self.attack_plan = _safe_json_dumps(structured)
        elif phase == "weaponize":
            self._upsert_phase_record(phase="weaponize", status="running", attempt=1)
            result = self.weaponize_agent.call(
                f"针对目标 {self.target_ip} 的未知服务，生成可直接在当前环境下运行的 Python 协议感知型动态探测代码。",
                context=context,
            )
            # 解析生成的代码并写入 sandbox
            code_match = re.search(r'```python\s*(.*?)\s*```', result, re.DOTALL)
            structured = {"weaponized": bool(code_match)}
            if code_match:
                sandbox_file = os.path.join(os.path.dirname(__file__), "pocs", DYNAMIC_PROBE_FILENAME)
                with open(sandbox_file, "w") as f:
                    f.write(_wrap_code_as_plugin(code_match.group(1)))
                self._add_log({"type": "success", "message": f"[Weaponize Agent] 成功投递并沙箱化未知服务动态探测脚本: {DYNAMIC_PROBE_FILENAME}"})
        elif phase == "execute":
            existing_error_items = [
                item for item in (self.structured_results.get("execution", {}).get("items") or [])
                if item.get("error")
            ]
            if existing_error_items:
                self._prune_attack_plan_after_failures(existing_error_items)
            self._upsert_phase_record(phase="execute", status="running", attempt=1)
            result, structured = self._execute_plan_stepwise()
            valid, reason = self._validate_execution_result(structured)
            if not valid:
                self._record_phase("execute", "error", result, structured, reason)
                self._require_phase_success("execute")
            else:
                self._record_phase("execute", "done", result, structured)
            self.structured_results["execution"] = structured
            self.execution_results = result
            self._supervise_execution_outcome()
        elif phase == "reflector":
            self._upsert_phase_record(phase="reflector", status="running", attempt=1)
            result, structured = self._run_reflector()
            self._upsert_phase_record(phase="reflector", status="done", attempt=1, raw_output=result, structured_output=structured)
            if structured.get("reentry_required"):
                self._record_supervisor_event(
                    "reflector_reentry_requested",
                    (
                        f"Reflector 请求回跳到 {structured.get('next_phase')}，"
                        f"next_action={structured.get('next_action')}，rerun_mode={structured.get('rerun_mode')}。"
                    ),
                    severity="warning",
                    phase="reflector",
                )
        elif phase == "assess":
            self._upsert_phase_record(phase="assess", status="running", attempt=1)
            result = self._run_assessment_phase(context=context)
            structured = dict(self.structured_results.get("assessment") or {})
            structured.setdefault("report_markdown", result)
            structured.setdefault("finding_count", len(self.findings))
            self.structured_results["assessment"] = structured
            self.final_report = result
        else:
            raise ValueError(f"Unknown phase: {phase}")

        self._add_log({"type": "success", "message": f"[√] 阶段 {friendly_name} 执行完毕"})
        self._refresh_supervisor_metrics()
        if phase in {"weaponize", "assess"}:
            self._record_phase(phase, "done", result, structured)
        self._refresh_llm_usage()
        response = {
            "result": result,
            "structured_result": structured,
            "llm_usage": self.structured_results.get("llm_usage", {}),
            "structured": self.structured_results,
            "logs": self.current_logs,
            "findings": self.findings,
            "phase_records": self.phase_records,
        }
        if phase == "reflector" and structured.get("reentry_required"):
            response["reroute"] = {
                "next_action": structured.get("next_action"),
                "next_phase": structured.get("next_phase"),
                "rerun_mode": structured.get("rerun_mode") or "from_phase",
                "focus_steps": structured.get("focus_steps") or [],
                "focus_pocs": structured.get("focus_pocs") or [],
                "reason": structured.get("reason") or structured.get("summary") or "",
            }
        if phase == "recon":
            gate = structured.get("attack_surface_gate") or self.structured_results.get("attack_surface_gate")
            if gate and gate.get("blocked"):
                response["skip_to_assess"] = True
                response["reroute"] = {
                    "next_action": "skip_to_assess",
                    "next_phase": "assess",
                    "reason": gate.get("reason") or "",
                }
        return response


# ──────────────────────────────────────────────
# CLI Entry Point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.100.1"
    name = sys.argv[2] if len(sys.argv) > 2 else "Vehicle Target"

    orch = AgentOrchestrator(target_ip=target, target_name=name)
    report = orch.run_full_assessment()

    print("\n" + "="*60)
    print("AUTO SECURITY ASSESSMENT REPORT")
    print("="*60)
    print(report["phases"]["assessment_report"])
    print("="*60)
    print(f"总耗时: {report['duration_seconds']}s")

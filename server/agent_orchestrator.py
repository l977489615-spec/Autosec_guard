"""
Multi-Agent Orchestrator — AutoSec Guard
==========================================
基于 OpenAI 兼容接口（DashScope/Qwen）实现的多 Agent 协作自主渗透测试系统。

4 个专业 Agent 通过调用 MCP Server 工具协作完成完整的车辆渗透测试闭环：

  ┌─────────────────────────────────────────────────────┐
  │  Agent 1 (侦察 Recon)                                │
  │   → scan_ports, get_topology                        │
  │   → 输出: 发现的服务列表、拓扑图、建议攻击向量        │
  └──────────────────┬──────────────────────────────────┘
                     │ 侦察结果
  ┌──────────────────▼──────────────────────────────────┐
  │  Agent 2 (决策 Decision)                             │
  │   → list_pocs, check_safety                         │
  │   → 输出: 有序攻击计划（PoC 执行序列 + 策略）         │
  └──────────────────┬──────────────────────────────────┘
                     │ 攻击计划
  ┌──────────────────▼──────────────────────────────────┐
  │  Agent 3 (执行 Executor)                             │
  │   → run_poc (循环, 含反馈调整)                       │
  │   → 输出: 所有 PoC 的执行结果 + 证据                 │
  └──────────────────┬──────────────────────────────────┘
                     │ 漏洞证据
  ┌──────────────────▼──────────────────────────────────┐
  │  Agent 4 (评估 Assessment)                           │
  │   → 生成符合 ISO 21434 / UN R155 的安全报告          │
  │   → 输出: 最终安全评估报告 JSON + 建议               │
  └─────────────────────────────────────────────────────┘

使用方法:
  from agent_orchestrator import AgentOrchestrator
  orch = AgentOrchestrator(target_ip="192.168.100.1", dashscope_api_key="YOUR_KEY")
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
import requests
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple
from config import get_config

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s')

CONFIG = get_config()

# MCP Server 地址
MCP_SERVER = CONFIG.mcp_server
DASHSCOPE_API_KEY = CONFIG.dashscope_api_key

# ──────────────────────────────────────────────
# MCP Tool Caller — 供 Agent 调用
# ──────────────────────────────────────────────

# 主 AutoSec API 地址（供 run_poc / list_pocs 调用）
AUTOSEC_API = CONFIG.autosec_api

PHASE_SEQUENCE = ["recon", "decision", "weaponize", "execute", "assess"]
PHASE_RETRY_LIMITS = {
    "recon": 2,
    "decision": 2,
    "weaponize": 1,
    "execute": 2,
    "assess": 1,
}
SUPERVISOR_LIMITS = {
    "max_consecutive_same_tool_call": 2,
    "max_consecutive_stalled_result": 2,
    "max_cascading_errors": 3,
}


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
    vulnerable: bool
    evidence: str = ""
    error: str = ""
    strategy: str = "default"
    branch: str = "primary"


def _safe_json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


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
        for key in ("attack_plan", "plan", "items", "steps", "tasks"):
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


def _direct_tool_call(
    tool_name: str,
    params: dict,
    on_log: Optional[callable] = None,
    tool_state: Optional[Dict[str, Any]] = None,
) -> dict:
    """
    直接本地调用扫描模块 — 不依赖 MCP Server 进程。
    当 MCP Server 未启动时自动降级到此路径。
    """
    try:
        if tool_name == "scan_ports":
            from topology_scanner import TopologyAwareScanner
            target_ip = params.get("target_ip")
            if on_log:
                on_log({"type": "info", "message": f"[Topology] 开始对 {target_ip} 的端口扫描..."})
            timeout = float(params.get("timeout", 2.0))
            scanner = TopologyAwareScanner(target_ip, timeout=timeout)
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
            target_ip = params.get("target_ip")
            if on_log:
                on_log({"type": "info", "message": f"[Topology] 正在分析 {target_ip} 的网络拓扑结构..."})
            scanner = TopologyAwareScanner(target_ip, timeout=3.0)
            topo = scanner.scan()
            if on_log:
                on_log({"type": "info", "message": f"[Topology] 拓扑分析完成: SEC-GW={topo.has_security_gateway}, 推荐向量={topo.recommended_attack_vector}"})
            return topo.to_dict()

        elif tool_name == "get_adaptive_context":
            from physical_safety_monitor import get_or_create_engine
            target_ip = params.get("target_ip")
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
            try:
                resp = requests.get(f"{AUTOSEC_API}/api/list_pocs", timeout=10)
                if resp.ok:
                    pocs = resp.json().get("pocs", [])
                    # [Sync ID Map]
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
            except Exception:
                pass
            # 降级：直接扫描 PoC 目录
            import glob
            pocs_dir = os.path.join(os.path.dirname(__file__), "pocs")
            files = glob.glob(os.path.join(pocs_dir, "**", "*.py"), recursive=True)
            pocs = [{"filename": os.path.relpath(f, pocs_dir),
                     "category_dir": os.path.basename(os.path.dirname(f))}
                    for f in files
                    if not os.path.basename(f).startswith("_")
                    and os.path.basename(f) != "iv_plugin_base.py"]
            if on_log:
                on_log({"type": "info", "message": f"[Scanner] 本地加载 {len(pocs)} 个 PoC 脚本"})
            return {"pocs": pocs, "count": len(pocs)}

        elif tool_name == "run_poc":
            poc_name = params.get("poc_name") or params.get("poc_file") or params.get("filename")
            poc_params = params.get("params", {})
            try:
                resp = requests.post(
                    f"{AUTOSEC_API}/api/run_poc",
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
                            status = "发现漏洞!" if data.get("vulnerable") else "未发现漏洞"
                            on_log({"type": "success" if data.get("vulnerable") else "info", "message": f"[Executor] PoC 执行完毕: {status}"})
                    return {
                        "blocked": False,
                        "vulnerable": data.get("vulnerable") or data.get("status") == "vulnerable",
                        "evidence": data.get("evidence") or data.get("output", ""),
                        "logs": data.get("logs", []),
                    }
                return {"blocked": False, "error": f"API {resp.status_code}: {resp.text[:200]}"}
            except Exception as e:
                return {"blocked": False, "error": str(e)}

        else:
            return {"error": f"Unknown tool: {tool_name}"}

    except Exception as e:
        logger.error(f"[DirectTool] {tool_name} 执行失败: {e}")
        return {"error": str(e)}


def call_mcp_tool(
    tool_name: str,
    params: dict,
    timeout: int = 90,
    on_log: Optional[callable] = None,
    tool_state: Optional[Dict[str, Any]] = None,
) -> dict:
    """
    调用 MCP 工具。
    优先连接外部 MCP Server（端口 5003）；
    连接失败时自动降级为直接本地执行，无需单独启动 mcp_server.py。
    """
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
# Qwen (OpenAI SDK) LLM 调用包装
# ──────────────────────────────────────────────

class QwenAgent:
    """
    单个 Qwen Agent — 封装 LLM 调用，支持通过函数调用驱动 MCP 工具
    """
    def __init__(self, agent_name: str, system_prompt: str, mcp_tools: List[dict],
                 model_name: str = "qwen-plus", max_turns: int = 8, on_log: Optional[callable] = None):
        self.agent_name = agent_name
        self.system_prompt = system_prompt
        self.mcp_tools = mcp_tools
        self._api_key = DASHSCOPE_API_KEY
        self._model_name = model_name
        self._max_turns = max_turns
        self.on_log = on_log
        self.tool_state: Dict[str, Any] = {}
        self.tool_history: List[Dict[str, Any]] = []
        self.supervisor_events: List[Dict[str, Any]] = []

    def _build_openai_tools(self) -> List[dict]:
        """将 MCP 工具格式转换为 OpenAI Function Calling 格式"""
        if not self.mcp_tools:
            return None
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
            "timestamp": datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        }
        self.supervisor_events.append(event)
        if self.on_log:
            self.on_log({
                "type": "warning" if severity != "info" else "info",
                "message": f"[Supervisor:{self.agent_name}] {message}",
            })

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
                f"[{self.agent_name}] DASHSCOPE_API_KEY 未配置。"
                "请确保 DASHSCOPE_API_KEY 已设置为环境变量。"
            )

        from openai import OpenAI
        client = OpenAI(
            api_key=self._api_key,
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1"
        )

        full_prompt = f"上下文信息:\n{context}\n\n任务:\n{user_message}"

        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": full_prompt}
        ]
        self.tool_history = []
        self.supervisor_events = []

        openai_tools = self._build_openai_tools()

        # 多轮工具调用循环（含 429 指数退避重试）
        for turn in range(self._max_turns):
            # 429 重试逻辑：最多重试 3 次，指数退避
            last_err = None
            response = None
            for attempt in range(3):
                try:
                    response = client.chat.completions.create(
                        model=self._model_name,
                        messages=messages,
                        tools=openai_tools
                    )
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

            message = response.choices[0].message

            # 如果没有工具调用，说明是最终文本响应
            if not message.tool_calls:
                return message.content or "Agent 未返回有效响应"

            # 记录助理的工具调用请求
            messages.append(message)

            # 执行所有工具调用
            for tool_call in message.tool_calls:
                tool_name = tool_call.function.name
                try:
                    tool_params = json.loads(tool_call.function.arguments)
                except Exception:
                    tool_params = {}
                
                logger.info(f"[{self.agent_name}] → MCP Tool Call: {tool_name}({json.dumps(tool_params, ensure_ascii=False)[:80]})")
                if self.on_log:
                    self.on_log({"type": "info", "message": f"[{self.agent_name}] 调用工具: {tool_name}({json.dumps(tool_params, ensure_ascii=False)[:60]}...)"})

                result = self._pre_tool_supervisor_guard(tool_name, tool_params)
                if result is None:
                    result = call_mcp_tool(
                        tool_name,
                        tool_params,
                        on_log=self.on_log,
                        tool_state=self.tool_state,
                    )
                result = self._post_tool_supervisor_guard(tool_name, tool_params, result)
                
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
                    "tool_call_id": tool_call.id,
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
1. 调用 list_pocs 查询可用的 PoC 验证模块列表
   • 注意：当前系统已全面升级为序号化命名规则（例如 10_SSH_Weak_Creds.py），请【必须】使用 list_pocs 返回的 filename 字段作为唯一执行标识。
2. 调用 get_adaptive_context 获取目标的服务指纹和认证类型
3. 批准过滤如下 PoC（不得将其列入攻击计划）：
   • 如果【可用资源】中没有 bluetooth_mac，则跳过所有荷包名包含 "bluetooth"/"BT"/"ble" 的 PoC
   • 如果【可用资源】中没有 can_interface，则跳过所有包含 "canbus"/"CAN"/"isotp" 的 PoC
   • 如果【可用资源】中没有 wifi_interface，则跳过所有包含 "wireless"/"wifi"/"wpa" 的 PoC
   • 跳过侦察结果中未发现对应服务相关的 PoC
4. 对剩余 PoC 调用 check_safety 获取推荐策略。如果你发现目标开启了某个完全未知的协议或者未涵盖在现有 PoC 中的异常服务，请在攻击计划中添加此项：`poc_name` 填 `"dynamic_0day"`，`strategy` 填 `"weaponize"`，并在 `parameters` 详细描述此服务的指纹。系统将触发 Weaponize Agent 动态生成 0-day 测试代码。
5. 输出有序的攻击计划 JSON，每个项包含： poc_name、parameters（含必要字段）、strategy、reason

注意：优先测试侦察中发现的开放端口对应的服务漏洞。以结构化 JSON 格式输出攻击计划。使用中文输出分析结论。
"""

WEAPONIZE_AGENT_PROMPT = """
你是一名全球顶级的 0-day 安全研究员，精通智能网联汽车的漏洞原语挖掘。
你的任务是：根据传入的“未知协议服务”信息，动态编写一段 Python 脚本（PoC）用于发送 Fuzzing payload 或探测包并收集漏洞证据。
【要求】：
1. 脚本必须是可以直接执行的完整 Python 代码。
2. 使用系统提供的参数进行测试。
3. 捕获所有异常，并在输出中告知测试结果。如果通过异常行为确信存在漏洞，请在控制台打印 "Vulnerable: True"。
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

ASSESSMENT_AGENT_PROMPT = """
你是一名资深汽车网络安全评估专家，精通 ISO/SAE 21434 和 UN R155 法规要求。
基于前序 Agent 的侦察数据、攻击计划和执行结果，你需要生成一份完整的安全评估报告。

━━ 最高优先级规则（强制） ━━

1. 绝对禁止编造、推测或补充任何未在【执行结果】中实际出现的漏洞。
2. 报告中提及的每一个漏洞，必须能在上下文提供的【执行结果】中找到对应的 PoC 执行记录和证据。
3. 如果某个攻击面（如 USB、RF 钥匙、固件更新等）未在【执行结果】中出现，则不得在报告中提及。
4. 不得引用“可能存在”、“潜在”、“推测”等模糊表述来描述未经实际测试的漏洞。
5. 如果执行结果中所有 PoC 均未发现漏洞，报告应如实反映“未发现漏洞”，而不是编造漏洞来填充报告。

━━ 报告结构 ━━

1. 执行摘要（Executive Summary）：面向管理层的风险概述，仅基于实际测试发现
2. 总体风险评级：CRITICAL / HIGH / MEDIUM / LOW（仅基于实际发现的漏洞评级）
3. 实际测试范围概述：明确列出本次实际执行了哪些 PoC 测试项
4. 漏洞详细分析：仅分析实际确认的漏洞，【重要】必须使用 ISO 21434 TARA (Threat Analysis and Risk Assessment) 风险矩阵格式呈现，包含：
   - 漏洞名称、协议类型、影响的 ECU 组件
   - 实际执行的 PoC 名称和返回的证据原文
   - TARA 威胁分析表格 (使用 Markdown 表格，包含列: 威胁场景 Threat Scenario | 影响程度 Impact Rating | 攻击可行性 Attack Feasibility | 风险等级 Risk Value)
   - CVSS 评分参考
5. 未发现漏洞的测试项：列出执行了但未发现漏洞的 PoC
6. 修复建议：仅针对实际确认的漏洞提供加固方案
7. 合规性评估：对照 UN R155 CSMS 要求的合规差距
8. 建议的后续测试：列出本次未覆盖但建议未来进行的测试领域（明确标注“未测试”）

━━ 格式要求 ━━

- 报告中的评估日期必须使用上下文中提供的当前时间，禁止自行编造日期
- 报告中的评估团队必须写 BIOS团队
- 使用正式专业的语言输出，Markdown 格式，使用中文
"""



# ──────────────────────────────────────────────
# 主协作编排器
# ──────────────────────────────────────────────

class AgentOrchestrator:
    """
    多 Agent 协作自主渗透测试编排器
    
    调度 4 个专业 Agent 完成从侦察到报告的完整渗透测试闭环。
    """

    def __init__(self, target_ip: str, target_name: str = "Vehicle Target",
                 dashscope_api_key: Optional[str] = None,
                 can_interface: str = "",
                 bluetooth_mac: str = "",
                 wifi_interface: str = ""):
        self.target_ip = target_ip
        self.target_name = target_name
        self.start_time = time.time()

        # 可用资源上下文（Agent 决策过滤依据）
        self.available_params: Dict[str, str] = {"target_ip": target_ip}
        if can_interface:
            self.available_params["can_interface"] = can_interface
        if bluetooth_mac:
            self.available_params["bluetooth_mac"] = bluetooth_mac
        if wifi_interface:
            self.available_params["wifi_interface"] = wifi_interface

        if dashscope_api_key:
            os.environ["DASHSCOPE_API_KEY"] = dashscope_api_key

        # 从 MCP Server 获取工具描述
        self.mcp_tools = self._load_mcp_tools()

        # 运行日志缓冲区
        self.current_logs: List[dict] = []
        self.phase_records: List[dict] = []
        self.execution_trace: List[dict] = []

        # 初始化 4 个 Agent
        self.recon_agent = QwenAgent("侦察Agent", RECON_AGENT_PROMPT, self.mcp_tools, on_log=self._add_log)
        self.planner_agent = QwenAgent("规划Agent", PLANNER_AGENT_PROMPT, [], model_name="qwen-plus", on_log=self._add_log)
        self.decision_agent = QwenAgent("决策Agent", DECISION_AGENT_PROMPT, self.mcp_tools, on_log=self._add_log)
        self.weaponize_agent = QwenAgent("Weaponize Agent", WEAPONIZE_AGENT_PROMPT, [], model_name="qwen-max", on_log=self._add_log)
        self.executor_agent = QwenAgent("执行Agent", EXECUTOR_AGENT_PROMPT, self.mcp_tools,
                                           max_turns=20, on_log=self._add_log)
        self.assessment_agent = QwenAgent("评估Agent", ASSESSMENT_AGENT_PROMPT, [],
                                            model_name="qwen-max", on_log=self._add_log)

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
            "assessment": {},
            "supervisor": {"events": [], "metrics": {}, "adjustments": []},
        }

        # 发现的漏洞清单 (Structured Findings)
        self.findings: List[dict] = []
        # PoC 文件名到 ID 的映射，用于完善 findings
        self.poc_filename_to_id = {}
        self._finding_names = set()

        tool_state = {"poc_filename_to_id": self.poc_filename_to_id}
        self.recon_agent.tool_state = tool_state
        self.decision_agent.tool_state = tool_state
        self.executor_agent.tool_state = tool_state

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
                "timestamp": datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
                "raw_output": "",
                "structured_output": {},
                "error": "",
                "history": [],
            }
            self.phase_records.append(existing)

        existing.update({
            "status": status,
            "attempt": max(existing.get("attempt", 0), attempt),
            "timestamp": datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
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
    ) -> Optional[dict]:
        if not poc_name or poc_name in self._finding_names:
            return None

        poc_id = self.poc_filename_to_id.get(poc_name) or self.poc_filename_to_id.get(os.path.basename(poc_name))
        finding = {
            "pocId": poc_id or poc_name,
            "name": poc_name,
            "vulnerable": True,
            "severity": severity,
            "description": evidence or f"自主扫描发现目标存在 {poc_name} 风险。",
            "details": evidence or "",
            "error": error,
            "source": source,
            "detectedAt": datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        }
        self.findings.append(finding)
        self._finding_names.add(poc_name)
        return finding

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

    def _normalize_attack_plan(self, raw_text: str) -> Dict[str, Any]:
        payload, parse_error = _extract_json_payload(raw_text)
        items = _normalize_plan_items(payload)
        return {
            "items": items,
            "summary": str(raw_text).strip(),
            "parse_error": parse_error,
            "item_count": len(items),
        }

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
            steps = payload.get("steps") or []
            normalized_steps = []
            for index, step in enumerate(steps, start=1):
                if not isinstance(step, dict):
                    continue
                normalized_steps.append({
                    "step": step.get("step") or index,
                    "title": step.get("title") or f"步骤 {index}",
                    "objective": step.get("objective") or "",
                    "success_criteria": step.get("success_criteria") or "",
                    "depends_on": step.get("depends_on") or [],
                })
            result["strategy_summary"] = payload.get("strategy_summary") or ""
            result["steps"] = normalized_steps
            result["guardrails"] = payload.get("guardrails") or []
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
        params = dict(branch.get("params") or {})
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
        return call_mcp_tool(
            "run_poc",
            {
                "poc_name": poc_name,
                "params": params,
            },
            on_log=self._add_log,
            tool_state=self.executor_agent.tool_state,
        )

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
        execution_items: List[Dict[str, Any]] = []
        consecutive_errors = 0

        for item in plan_items:
            step = item.get("step")
            poc_name = item.get("poc_name")
            if item.get("status") == "skipped_by_supervisor":
                execution_items.append(asdict(ExecutionResultItem(
                    step=step or len(execution_items) + 1,
                    poc_name=poc_name or f"step_{len(execution_items) + 1}",
                    status="skipped_by_supervisor",
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
                branch_result = {
                    "branch": active_branch,
                    "success": bool(result.get("success", not result.get("error"))),
                    "blocked": bool(result.get("blocked")),
                    "vulnerable": bool(result.get("vulnerable")),
                    "error": result.get("error", ""),
                    "evidence": result.get("evidence", ""),
                    "strategy_branch": result.get("strategy_branch") or branch.get("name"),
                }
                branch_results.append(branch_result)

                error = branch_result["error"]
                vulnerable = branch_result["vulnerable"]
                evidence = branch_result["evidence"]

                if branch_result["blocked"]:
                    status = "blocked"
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
            )))
            execution_items[-1]["branch_results"] = branch_results
            item["status"] = status

            if consecutive_errors >= SUPERVISOR_LIMITS["max_cascading_errors"]:
                self._record_supervisor_event(
                    "execution_error_spread",
                    "逐步执行过程中检测到连续错误，Supervisor 已提前终止后续高风险步骤。",
                    severity="error",
                    phase="execute",
                )
                self.structured_results["execution"] = {
                    "items": execution_items,
                    "summary": self._summarize_execution_items(execution_items),
                    "parse_error": None,
                    "item_count": len(execution_items),
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
            "timestamp": datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
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
            "timestamp": datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
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

    def _merge_agent_supervisor_events(self, agent: QwenAgent, phase: str):
        for event in getattr(agent, "supervisor_events", []) or []:
            self._record_supervisor_event(
                event.get("scope", "agent_supervision"),
                event.get("message", ""),
                severity=event.get("severity", "warning"),
                phase=phase,
            )

    def _run_planner(self):
        planner_raw = self.planner_agent.call(
            f"为目标 {self.target_ip} 生成执行纲要。",
            context=(
                f"{self._build_available_params_context()}\n\n"
                f"侦察结果(JSON):\n{_safe_json_dumps(self.structured_results['recon'])}"
            ),
        )
        planner_structured = self._normalize_planner_result(planner_raw)
        if not planner_structured.get("steps"):
            planner_structured = self._fallback_planner_result()
            self._record_supervisor_event(
                "planner_fallback",
                "规划 Agent 未返回有效步骤，已回退到内置执行纲要。",
                phase="decision",
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
        return "【可用资源】\n" + "\n".join(f"  - {p}" for p in parts)

    def hydrate_state(self, state: Dict[str, Any]):
        self.current_logs = state.get("logs", []) or []
        self.phase_records = state.get("phase_records", []) or []
        self.findings = state.get("findings", []) or []
        self._finding_names = {item.get("name") for item in self.findings if item.get("name")}
        structured = state.get("structured", {}) or {}
        self.structured_results["recon"] = structured.get("recon", self.structured_results["recon"])
        self.structured_results["planner"] = structured.get("planner", self.structured_results["planner"])
        self.structured_results["attack_plan"] = structured.get("decision", structured.get("attack_plan", self.structured_results["attack_plan"]))
        self.structured_results["execution"] = structured.get("execute", structured.get("execution", self.structured_results["execution"]))
        self.structured_results["assessment"] = structured.get("assess", structured.get("assessment", self.structured_results["assessment"]))
        self.structured_results["supervisor"] = structured.get("supervisor", self.structured_results["supervisor"])
        recon_record = self._get_phase_record("recon")
        decision_record = self._get_phase_record("decision")
        execute_record = self._get_phase_record("execute")
        assess_record = self._get_phase_record("assess")
        self.recon_result = recon_record.get("raw_output") if recon_record else self.recon_result
        self.attack_plan = decision_record.get("raw_output") if decision_record else self.attack_plan
        self.execution_results = execute_record.get("raw_output") if execute_record else self.execution_results
        self.final_report = assess_record.get("raw_output") if assess_record else self.final_report
        self._refresh_supervisor_metrics()

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
        items = structured.get("items") or []
        if items or self.findings:
            return True, ""
        if structured.get("parse_error"):
            return False, f"执行结果无法解析为 JSON: {structured['parse_error']}"
        return False, "执行结果为空，未返回任何 PoC 结果"

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

    def _build_assessment_call(self, context: str = "") -> Dict[str, str]:
        """为评估 Agent 统一构造报告元数据，禁止模型自行编造日期或团队。"""
        report_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target_name = self.target_name or self.target_ip or "Unknown Target"

        prompt = (
            f"基于对智能网联汽车目标 '{target_name}' ({self.target_ip}) 的完整渗透测试结果，"
            "生成符合 ISO 21434 / UN R155 要求的专业安全评估报告。"
            f"【当前时间】{report_date}。"
            f"报告中的评估日期必须写 {report_date}，评估团队必须写 BIOS团队。"
        )

        context_prefix = (
            f"【当前时间】{report_date}\n"
            f"【评估日期】{report_date}\n"
            f"【评估团队】BIOS团队\n"
            f"【评估目标】{target_name}\n"
            f"【目标IP】{self.target_ip}\n\n"
        )

        return {
            "prompt": prompt,
            "context": f"{context_prefix}{context or ''}",
        }

    def _add_log(self, entry: Any):
        """添加一条日志到缓冲区"""
        if isinstance(entry, dict):
            # 补全时间戳（如果缺失）
            if "timestamp" not in entry:
                entry["timestamp"] = time.strftime("%H:%M:%S")
            self.current_logs.append(entry)
            
            # [新逻辑] 自动捕获漏洞发现：如果日志消息中包含“发现漏洞!”且来自 Executor，则记录到 findings
            # 这种方式最鲁棒，因为 _direct_tool_call 已经处理了 vulnerable 逻辑
            # [优化] 直接从日志消息中提取文件名
            msg = entry.get("message", "")
            if "[Executor] PoC 执行完毕: 发现漏洞!" in msg:
                match = re.search(r'\(文件名:\s*([^)]+)\)', msg)
                if match:
                    poc_name = match.group(1).strip()
                else:
                    # 兼容性回滚：回溯查找最近的工具调用
                    poc_name = "未知漏洞"
                    for prev in reversed(self.current_logs[:-1]):
                        if "调用工具: run_poc" in prev.get("message", ""):
                            n_match = re.search(r'poc_name":\s*"([^"]+)"', prev.get("message", ""))
                            if n_match:
                                poc_name = n_match.group(1)
                            break
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

    def run_full_assessment(self) -> Dict[str, Any]:
        """
        执行完整的 4-Agent 协作渗透测试评估
        返回包含所有阶段结果的综合报告字典
        """
        logger.info(f"[Orchestrator] ===== 开始自主协作渗透测试: {self.target_name} ({self.target_ip}) =====")
        self.phase_records = []
        self.execution_trace = []
        self.structured_results["supervisor"] = {"events": [], "metrics": {}, "adjustments": []}
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
        _available_params_ctx = "【可用资源】\n" + "\n".join(f"  - {p}" for p in _params_desc_parts)

        # ── Phase 1: 侦察 ──
        logger.info("[Orchestrator] Phase 1/4: 侦察 Agent 开始执行...")
        self.recon_result, self.structured_results["recon"] = self._call_agent_with_validation(
            phase="recon",
            agent=self.recon_agent,
            user_message=(
            f"对目标 {self.target_ip}（{self.target_name}）执行完整侦察。"
            f"使用 scan_ports 发现开放服务，使用 get_topology 建立网络拓扑图，"
            f"使用 get_adaptive_context 获取目标服务指纹和认证机制。"
            f"输出 JSON 格式的侦察摘要。"
            ),
            context=_available_params_ctx,
            normalizer=self._normalize_recon_result,
            validator=self._validate_recon_result,
            correction_hint=(
                "输出必须是 JSON 对象，至少包含 summary、open_ports、services、topology、adaptive_context 字段。"
            ),
        )
        self._require_phase_success("recon")
        self._merge_agent_supervisor_events(self.recon_agent, "recon")
        logger.info(f"[Orchestrator] Phase 1 完成:\n{self.recon_result[:300]}...")

        planner_result, planner_structured = self._run_planner()
        self.structured_results["planner"] = planner_structured
        logger.info(f"[Orchestrator] Planner 完成:\n{planner_result[:200]}...")

        # ── Phase 2: 决策规划 ──
        logger.info("[Orchestrator] Phase 2/4: 决策 Agent 开始规划攻击路径...")
        self.attack_plan, self.structured_results["attack_plan"] = self._call_agent_with_validation(
            phase="decision",
            agent=self.decision_agent,
            user_message=(
            f"基于侦察结果和以下可用资源，规划针对 {self.target_ip} 的渗透测试计划。"
            f"严格按照【可用资源】中的参数过滤 PoC：缺少 bluetooth_mac 则不选择蓝牙 PoC，"
            f"缺少 can_interface 则不选择 CAN 总线 PoC，缺少 wifi_interface 则不选择无线嗅探 PoC。"
            f"输出有序的 JSON 攻击计划，每项包含 poc_name 和 parameters 字段（parameters 中包含实际参数值）。"
            ),
            context=(
                f"{_available_params_ctx}\n\n"
                f"侦察结果(JSON):\n{_safe_json_dumps(self.structured_results['recon'])}\n\n"
                f"执行纲要(JSON):\n{_safe_json_dumps(self.structured_results['planner'])}"
            ),
            normalizer=self._normalize_attack_plan,
            validator=self._validate_attack_plan,
            correction_hint=(
                "输出必须是 JSON 数组或包含 items/attack_plan 字段的 JSON 对象。"
                "每个步骤必须包含 poc_name、parameters、strategy、reason。"
            ),
        )
        self._require_phase_success("decision")
        self._merge_agent_supervisor_events(self.decision_agent, "decision")
        self._supervise_attack_plan()
        self.execution_trace = list(self.structured_results["attack_plan"]["items"])
        logger.info(f"[Orchestrator] Phase 2 完成:\n{self.attack_plan[:300]}...")


        # ── Phase 2.5: 群智 Weaponize (Dynamic 0-day) ──
        if any(item["poc_name"] == "dynamic_0day" for item in self.structured_results["attack_plan"]["items"]):
            logger.info("[Orchestrator] Plan 包含 dynamic_0day，触发 Weaponize Agent 介入...")
            self._add_log({"type": "warning", "message": "[Orchestrator] 核心系统检测到未知协议，已紧急呼叫 Weaponize Agent 动态下发针对性利用载荷..."})
            weaponize_result = self.weaponize_agent.call(
                f"针对目标 {self.target_ip} 的未知服务，生成可直接在当前环境下运行的 Python Fuzzing/Exploit 代码。",
                context=(
                    f"侦察结果(JSON):\n{_safe_json_dumps(self.structured_results['recon'])}\n\n"
                    f"攻击计划(JSON):\n{_safe_json_dumps(self.structured_results['attack_plan'])}"
                )
            )
            # 解析生成的代码并写入 sandbox
            code_match = re.search(r'```python\s*(.*?)\s*```', weaponize_result, re.DOTALL)
            if code_match:
                sandbox_file = os.path.join(os.path.dirname(__file__), "pocs", "99_Dynamic_0Day.py")
                with open(sandbox_file, "w") as f:
                    f.write(code_match.group(1))
                for item in self.structured_results["attack_plan"]["items"]:
                    if item["poc_name"] == "dynamic_0day":
                        item["poc_name"] = "99_Dynamic_0Day.py"
                        item["status"] = "weaponized"
                self.attack_plan = _safe_json_dumps(self.structured_results["attack_plan"])
                self._add_log({"type": "success", "message": "[Weaponize Agent] 成功投递并沙箱化 0-day 探测脚本: 99_Dynamic_0Day.py"})
            else:
                self._add_log({"type": "info", "message": "[Weaponize Agent] 生成探测代码失败，跳过。输出: " + weaponize_result[:100]})
            self._record_phase(
                "weaponize",
                "done" if code_match else "error",
                weaponize_result,
                {"weaponized": bool(code_match)},
                "" if code_match else "dynamic 0-day generation failed",
            )
            self._require_phase_success("weaponize")
        else:
            self._record_phase("weaponize", "skipped", "", {"weaponized": False})


        # ── Phase 3: 执行 ──
        logger.info("[Orchestrator] Phase 3/4: 执行 Agent 开始逐步执行渗透测试...")
        self._upsert_phase_record(phase="execute", status="running", attempt=1)
        self.execution_results, self.structured_results["execution"] = self._execute_plan_stepwise()
        valid, reason = self._validate_execution_result(self.structured_results["execution"])
        if not valid:
            self._record_phase("execute", "error", self.execution_results, self.structured_results["execution"], reason)
            self._require_phase_success("execute")
        else:
            self._record_phase("execute", "done", self.execution_results, self.structured_results["execution"])
        self._supervise_execution_outcome()
        logger.info(f"[Orchestrator] Phase 3 完成:\n{self.execution_results[:300]}...")

        # ── Phase 4: 安全评估报告 ──
        logger.info("[Orchestrator] Phase 4/4: 评估 Agent 生成安全评估报告...")
        assessment_input = self._build_assessment_call(
            context=(
                f"侦察结果:\n{self.recon_result}\n\n"
                f"攻击计划(JSON):\n{_safe_json_dumps(self.structured_results['attack_plan'])}\n\n"
                f"执行结果(JSON):\n{_safe_json_dumps(self.structured_results['execution'])}\n\n"
                f"漏洞发现(JSON):\n{_safe_json_dumps(self.findings)}"
            )
        )
        self.final_report = self.assessment_agent.call(
            assessment_input["prompt"],
            context=assessment_input["context"],
        )
        self.structured_results["assessment"] = {
            "report_markdown": self.final_report,
            "finding_count": len(self.findings),
        }
        self._record_phase("assess", "done", self.final_report, self.structured_results["assessment"])
        logger.info("[Orchestrator] Phase 4 完成，报告已生成。")
        self._refresh_supervisor_metrics()

        duration = round(time.time() - self.start_time, 1)
        logger.info(f"[Orchestrator] ===== 自主渗透测试完成，总耗时 {duration}s =====")

        return {
            "target_ip": self.target_ip,
            "target_name": self.target_name,
            "duration_seconds": duration,
            "logs": self.current_logs,
            "phase_records": self.phase_records,
            "findings": self.findings,
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
        start_index = PHASE_SEQUENCE.index(start_phase)

        if start_index <= PHASE_SEQUENCE.index("recon"):
            return self.run_full_assessment()

        if start_index <= PHASE_SEQUENCE.index("decision"):
            if not self.structured_results.get("planner", {}).get("steps"):
                self._run_planner()
            self.attack_plan, self.structured_results["attack_plan"] = self._call_agent_with_validation(
                phase="decision",
                agent=self.decision_agent,
                user_message=(
                    f"基于侦察结果和以下可用资源，规划针对 {self.target_ip} 的渗透测试计划。"
                    f"严格按照【可用资源】中的参数过滤 PoC：缺少 bluetooth_mac 则不选择蓝牙 PoC，"
                    f"缺少 can_interface 则不选择 CAN 总线 PoC，缺少 wifi_interface 则不选择无线嗅探 PoC。"
                    f"输出有序的 JSON 攻击计划，每项包含 poc_name 和 parameters 字段（parameters 中包含实际参数值）。"
                ),
                context=(
                    f"{available_params_ctx}\n\n"
                    f"侦察结果(JSON):\n{_safe_json_dumps(self.structured_results['recon'])}\n\n"
                    f"执行纲要(JSON):\n{_safe_json_dumps(self.structured_results['planner'])}"
                ),
                normalizer=self._normalize_attack_plan,
                validator=self._validate_attack_plan,
                correction_hint="输出必须是 JSON 数组或包含 items/attack_plan 字段的 JSON 对象。每个步骤必须包含 poc_name、parameters、strategy、reason。",
            )
            self._require_phase_success("decision")
            self._merge_agent_supervisor_events(self.decision_agent, "decision")
            self._supervise_attack_plan()

        if any(item["poc_name"] == "dynamic_0day" for item in self.structured_results["attack_plan"]["items"]):
            logger.info("[Orchestrator] 恢复执行时检测到 dynamic_0day，重新触发 Weaponize Agent...")
            weaponize_result = self.weaponize_agent.call(
                f"针对目标 {self.target_ip} 的未知服务，生成可直接在当前环境下运行的 Python Fuzzing/Exploit 代码。",
                context=(
                    f"侦察结果(JSON):\n{_safe_json_dumps(self.structured_results['recon'])}\n\n"
                    f"攻击计划(JSON):\n{_safe_json_dumps(self.structured_results['attack_plan'])}"
                )
            )
            code_match = re.search(r'```python\s*(.*?)\s*```', weaponize_result, re.DOTALL)
            if code_match:
                sandbox_file = os.path.join(os.path.dirname(__file__), "pocs", "99_Dynamic_0Day.py")
                with open(sandbox_file, "w") as f:
                    f.write(code_match.group(1))
                for item in self.structured_results["attack_plan"]["items"]:
                    if item["poc_name"] == "dynamic_0day":
                        item["poc_name"] = "99_Dynamic_0Day.py"
                        item["status"] = "weaponized"
                self.attack_plan = _safe_json_dumps(self.structured_results["attack_plan"])
                self._record_phase("weaponize", "done", weaponize_result, {"weaponized": True})
            else:
                self._record_phase("weaponize", "error", weaponize_result, {"weaponized": False}, "dynamic 0-day generation failed")
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

        assessment_input = self._build_assessment_call(
            context=(
                f"侦察结果:\n{self.recon_result}\n\n"
                f"攻击计划(JSON):\n{_safe_json_dumps(self.structured_results['attack_plan'])}\n\n"
                f"执行结果(JSON):\n{_safe_json_dumps(self.structured_results['execution'])}\n\n"
                f"漏洞发现(JSON):\n{_safe_json_dumps(self.findings)}"
            )
        )
        self.final_report = self.assessment_agent.call(
            assessment_input["prompt"],
            context=assessment_input["context"],
        )
        self.structured_results["assessment"] = {
            "report_markdown": self.final_report,
            "finding_count": len(self.findings),
        }
        self._record_phase("assess", "done", self.final_report, self.structured_results["assessment"])
        self._refresh_supervisor_metrics()

        duration = round(time.time() - self.start_time, 1)
        return {
            "target_ip": self.target_ip,
            "target_name": self.target_name,
            "duration_seconds": duration,
            "logs": self.current_logs,
            "phase_records": self.phase_records,
            "findings": self.findings,
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
        self.current_logs = []  # 清空前一阶段日志
        self.phase_records = []
        self._upsert_phase_record(phase=phase, status="pending")
        PHASE_NAMES = {
            "recon": "侦察 (Reconnaissance)",
            "decision": "决策与规划 (Decision & Planning)",
            "weaponize": "零日探索 (Weaponization & 0-Day Fuzzing)",
            "execute": "自主攻击执行 (Autonomous Execution)",
            "assess": "报告生成与风险评估 (Risk Assessment)"
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
        elif phase == "decision":
            if self.structured_results.get("recon", {}).get("open_ports") and not self.structured_results.get("planner", {}).get("steps"):
                self._run_planner()
            result, structured = self._call_agent_with_validation(
                phase="decision",
                agent=self.decision_agent,
                user_message=f"规划针对 {self.target_ip} 的渗透测试计划。",
                context=(
                    f"{context}\n\n执行纲要(JSON):\n{_safe_json_dumps(self.structured_results['planner'])}"
                    if self.structured_results.get("planner", {}).get("steps")
                    else context
                ),
                normalizer=self._normalize_attack_plan,
                validator=self._validate_attack_plan,
                correction_hint="输出必须是 JSON 数组或包含 attack_plan/items 的 JSON 对象。",
            )
            self._require_phase_success("decision")
            self._merge_agent_supervisor_events(self.decision_agent, "decision")
            self.structured_results["attack_plan"] = structured
            self._supervise_attack_plan()
        elif phase == "weaponize":
            self._upsert_phase_record(phase="weaponize", status="running", attempt=1)
            result = self.weaponize_agent.call(
                f"针对目标 {self.target_ip} 的未知服务，生成可直接在当前环境下运行的 Python Fuzzing/Exploit 代码。",
                context=context,
            )
            # 解析生成的代码并写入 sandbox
            code_match = re.search(r'```python\s*(.*?)\s*```', result, re.DOTALL)
            structured = {"weaponized": bool(code_match)}
            if code_match:
                sandbox_file = os.path.join(os.path.dirname(__file__), "pocs", "99_Dynamic_0Day.py")
                with open(sandbox_file, "w") as f:
                    f.write(code_match.group(1))
                self._add_log({"type": "success", "message": "[Weaponize Agent] 成功投递并沙箱化 0-day 探测脚本: 99_Dynamic_0Day.py"})
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
            self._supervise_execution_outcome()
        elif phase == "assess":
            self._upsert_phase_record(phase="assess", status="running", attempt=1)
            assessment_input = self._build_assessment_call(context=context)
            result = self.assessment_agent.call(
                assessment_input["prompt"],
                context=assessment_input["context"],
            )
            structured = {"report_markdown": result, "finding_count": len(self.findings)}
            self.structured_results["assessment"] = structured
        else:
            raise ValueError(f"Unknown phase: {phase}")

        self._add_log({"type": "success", "message": f"[√] 阶段 {friendly_name} 执行完毕"})
        self._refresh_supervisor_metrics()
        if phase in {"weaponize", "assess"}:
            self._record_phase(phase, "done", result, structured)
        return {
            "result": result,
            "structured_result": structured,
            "logs": self.current_logs,
            "findings": self.findings,
            "phase_records": self.phase_records,
        }


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

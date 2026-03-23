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
import logging
import asyncio
import requests
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s')

# MCP Server 地址
MCP_SERVER = os.environ.get("MCP_SERVER", "http://localhost:5003")
DASHSCOPE_API_KEY = os.environ.get("DASHSCOPE_API_KEY") or os.environ.get("API_KEY")

# 如果环境变量未设置，自动从 client/.env.local 加载（无需手动 export）
if not DASHSCOPE_API_KEY:
    _env_candidates = [
        os.path.join(os.path.dirname(__file__), "..", "client", ".env.local"),
        os.path.join(os.path.dirname(__file__), "..", ".env.local"),
        os.path.join(os.path.dirname(__file__), ".env"),
    ]
    for _env_path in _env_candidates:
        _env_path = os.path.abspath(_env_path)
        if os.path.exists(_env_path):
            with open(_env_path) as _f:
                for _line in _f:
                    _line = _line.strip()
                    if _line.startswith("DASHSCOPE_API_KEY=") and not _line.startswith("#"):
                        DASHSCOPE_API_KEY = _line.split("=", 1)[1].strip().strip('"').strip("'")
                        os.environ["DASHSCOPE_API_KEY"] = DASHSCOPE_API_KEY
                        logger.info(f"[Orchestrator] DASHSCOPE_API_KEY 已从 {_env_path} 自动加载")
                        break
            if DASHSCOPE_API_KEY:
                break



# ──────────────────────────────────────────────
# MCP Tool Caller — 供 Agent 调用
# ──────────────────────────────────────────────

# 主 AutoSec API 地址（供 run_poc / list_pocs 调用）
AUTOSEC_API = os.environ.get("AUTOSEC_API", "http://localhost:5002")


def _direct_tool_call(tool_name: str, params: dict) -> dict:
    """
    直接本地调用扫描模块 — 不依赖 MCP Server 进程。
    当 MCP Server 未启动时自动降级到此路径。
    """
    try:
        if tool_name == "scan_ports":
            from topology_scanner import TopologyAwareScanner
            target_ip = params.get("target_ip")
            timeout = float(params.get("timeout", 2.0))
            scanner = TopologyAwareScanner(target_ip, timeout=timeout)
            scanner._scan_ports()
            nodes = scanner.topo_map.nodes
            open_ports = nodes[0].open_ports if nodes else []
            services = getattr(nodes[0], "services", []) if nodes else []
            return {"target_ip": target_ip, "open_ports": open_ports,
                    "services": services, "port_count": len(open_ports)}

        elif tool_name == "get_topology":
            from topology_scanner import TopologyAwareScanner
            target_ip = params.get("target_ip")
            scanner = TopologyAwareScanner(target_ip, timeout=3.0)
            topo = scanner.scan()
            return topo.to_dict()

        elif tool_name == "get_adaptive_context":
            from physical_safety_monitor import get_or_create_engine
            target_ip = params.get("target_ip")
            open_ports = params.get("open_ports") or []
            if isinstance(open_ports, str):
                open_ports = [int(p) for p in open_ports.split(",") if p.strip().isdigit()]
            engine = get_or_create_engine(target_ip)
            return engine.initialize(open_ports)

        elif tool_name == "check_safety":
            from physical_safety_monitor import get_or_create_engine
            target_ip = params.get("target_ip", "")
            poc_name = params.get("poc_name", "")
            protocol = params.get("protocol", "")
            if not target_ip:
                return {"should_run": True, "strategy": "default", "reason": "No context"}
            engine = get_or_create_engine(target_ip)
            skip, reason = engine.should_skip_poc(poc_name, protocol)
            strategy = engine.get_adaptive_strategy_for(protocol) if protocol else "default"
            return {
                "should_run": not skip,
                "strategy": strategy,
                "recommended_interval_s": engine.get_throttle_delay(),
                "reason": reason or "Context check passed",
            }

        elif tool_name == "list_pocs":
            # 调用本地 API 获取 PoC 列表（无需认证）
            try:
                resp = requests.get(f"{AUTOSEC_API}/api/list_pocs", timeout=10)
                if resp.ok:
                    pocs = resp.json().get("pocs", [])
                    cat = params.get("category")
                    if cat:
                        pocs = [p for p in pocs if cat.lower() in p.get("category", "").lower()]
                    return {"pocs": pocs, "count": len(pocs)}
            except Exception:
                pass
            # 降级：直接扫描 PoC 目录
            import glob
            pocs_dir = os.path.join(os.path.dirname(__file__), "pocs")
            files = glob.glob(os.path.join(pocs_dir, "**", "*.py"), recursive=True)
            pocs = [{"filename": os.path.relpath(f, pocs_dir),
                     "category": os.path.basename(os.path.dirname(f))}
                    for f in files
                    if not os.path.basename(f).startswith("_")
                    and os.path.basename(f) != "iv_plugin_base.py"]
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


def call_mcp_tool(tool_name: str, params: dict, timeout: int = 90) -> dict:
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
            return resp.json().get("result", {})
    except requests.exceptions.ConnectionError:
        pass  # MCP Server 未运行，降级到直接调用
    except Exception:
        pass

    # 降级：直接本地执行
    logger.debug(f"[MCP→Direct] {tool_name} (MCP Server 不可达，使用本地执行)")
    return _direct_tool_call(tool_name, params)




# ──────────────────────────────────────────────
# Qwen (OpenAI SDK) LLM 调用包装
# ──────────────────────────────────────────────

class QwenAgent:
    """
    单个 Qwen Agent — 封装 LLM 调用，支持通过函数调用驱动 MCP 工具
    """
    def __init__(self, agent_name: str, system_prompt: str, mcp_tools: List[dict],
                 model_name: str = "qwen-plus", max_turns: int = 8):
        self.agent_name = agent_name
        self.system_prompt = system_prompt
        self.mcp_tools = mcp_tools
        self._api_key = DASHSCOPE_API_KEY
        self._model_name = model_name
        self._max_turns = max_turns

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
                        logger.error(f"[{self.agent_name}] API 错误: {err_str[:200]}")
                        return f"[{self.agent_name}] API 错误: {err_str[:300]}"
            if last_err or not response:
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

                result = call_mcp_tool(tool_name, tool_params)
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
2. 调用 get_adaptive_context 获取目标的服务指纹和认证类型
3. 批准过滤如下 PoC（不得将其列入攻击计划）：
   • 如果【可用资源】中没有 bluetooth_mac，则跳过所有荷包名包含 "bluetooth"/"BT"/"ble" 的 PoC
   • 如果【可用资源】中没有 can_interface，则跳过所有包含 "canbus"/"CAN"/"isotp" 的 PoC
   • 如果【可用资源】中没有 wifi_interface，则跳过所有包含 "wireless"/"wifi"/"wpa" 的 PoC
   • 跳过侦察结果中未发现对应服务相关的 PoC
4. 对剩余 PoC 调用 check_safety 获取推荐策略
5. 输出有序的攻击计划 JSON，每个项包含： poc_name、parameters（含必要字段）、strategy、reason

注意：优先测试侦察中发现的开放端口对应的服务漏洞。以结构化 JSON 格式输出攻击计划。使用中文输出分析结论。
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
4. 漏洞详细分析：仅分析实际确认的漏洞，包含：
   - 漏洞名称、协议类型、影响的 ECU 组件
   - 实际执行的 PoC 名称和返回的证据原文
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

        # 初始化 4 个 Agent
        self.recon_agent = QwenAgent("侦察Agent", RECON_AGENT_PROMPT, self.mcp_tools)
        self.decision_agent = QwenAgent("决策Agent", DECISION_AGENT_PROMPT, self.mcp_tools)
        self.executor_agent = QwenAgent("执行Agent", EXECUTOR_AGENT_PROMPT, self.mcp_tools,
                                           max_turns=20)
        self.assessment_agent = QwenAgent("评估Agent", ASSESSMENT_AGENT_PROMPT, [],
                                            model_name="qwen-max")

        # 结果存储
        self.recon_result: Optional[str] = None
        self.attack_plan: Optional[str] = None
        self.execution_results: Optional[str] = None
        self.final_report: Optional[str] = None

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
        self.recon_result = self.recon_agent.call(
            f"对目标 {self.target_ip}（{self.target_name}）执行完整侦察。"
            f"使用 scan_ports 发现开放服务，使用 get_topology 建立网络拓扑图，"
            f"使用 get_adaptive_context 获取目标服务指纹和认证机制。"
            f"输出 JSON 格式的侦察摘要。",
            context=_available_params_ctx,
        )
        logger.info(f"[Orchestrator] Phase 1 完成:\n{self.recon_result[:300]}...")

        # ── Phase 2: 决策规划 ──
        logger.info("[Orchestrator] Phase 2/4: 决策 Agent 开始规划攻击路径...")
        self.attack_plan = self.decision_agent.call(
            f"基于侦察结果和以下可用资源，规划针对 {self.target_ip} 的渗透测试计划。"
            f"严格按照【可用资源】中的参数过滤 PoC：缺少 bluetooth_mac 则不选择蓝牙 PoC，"
            f"缺少 can_interface 则不选择 CAN 总线 PoC，缺少 wifi_interface 则不选择无线嗅探 PoC。"
            f"输出有序的 JSON 攻击计划，每项包含 poc_name 和 parameters 字段（parameters 中包含实际参数值）。",
            context=f"{_available_params_ctx}\n\n侦察结果:\n{self.recon_result}",
        )
        logger.info(f"[Orchestrator] Phase 2 完成:\n{self.attack_plan[:300]}...")


        # ── Phase 3: 执行 ──
        logger.info("[Orchestrator] Phase 3/4: 执行 Agent 开始逐步执行渗透测试...")
        self.execution_results = self.executor_agent.call(
            f"按照攻击计划，对目标 {self.target_ip} 执行所有 PoC 测试。"
            f"动态调整策略，记录所有证据。输出 JSON 格式的执行结果汇总。",
            context=f"侦察结果:\n{self.recon_result}\n\n攻击计划:\n{self.attack_plan}",
        )
        logger.info(f"[Orchestrator] Phase 3 完成:\n{self.execution_results[:300]}...")

        # ── Phase 4: 安全评估报告 ──
        logger.info("[Orchestrator] Phase 4/4: 评估 Agent 生成安全评估报告...")
        from datetime import datetime as _dt
        _now_str = _dt.now().strftime("%Y年%m月%d日 %H:%M:%S")
        self.final_report = self.assessment_agent.call(
            f"基于对智能网联汽车目标 '{self.target_name}'({self.target_ip}) 的完整渗透测试结果，"
            f"生成符合 ISO 21434 / UN R155 要求的专业安全评估报告。"
            f"【当前时间】{_now_str}。报告中的评估日期必须写 {_now_str}，评估团队必须写 BIOS团队。",
            context=(
                f"【当前时间】{_now_str}\n"
                f"【评估团队】BIOS团队\n\n"
                f"侦察结果:\n{self.recon_result}\n\n"
                f"攻击计划:\n{self.attack_plan}\n\n"
                f"执行结果:\n{self.execution_results}"
            ),
        )
        logger.info("[Orchestrator] Phase 4 完成，报告已生成。")

        duration = round(time.time() - self.start_time, 1)
        logger.info(f"[Orchestrator] ===== 自主渗透测试完成，总耗时 {duration}s =====")

        return {
            "target_ip": self.target_ip,
            "target_name": self.target_name,
            "duration_seconds": duration,
            "phases": {
                "recon": self.recon_result,
                "attack_plan": self.attack_plan,
                "execution": self.execution_results,
                "assessment_report": self.final_report,
            }
        }

    def run_phase(self, phase: str, context: str = "") -> str:
        """单独执行某一 Phase（供 API 调用）"""
        if phase == "recon":
            return self.recon_agent.call(
                f"对目标 {self.target_ip} 执行侦察。使用 scan_ports + get_topology。"
            )
        elif phase == "decision":
            return self.decision_agent.call(
                f"规划针对 {self.target_ip} 的渗透测试计划。",
                context=context,
            )
        elif phase == "execute":
            return self.executor_agent.call(
                f"执行针对 {self.target_ip} 的渗透测试。",
                context=context,
            )
        elif phase == "assess":
            return self.assessment_agent.call(
                f"生成目标 {self.target_ip} 的安全评估报告。",
                context=context,
            )
        else:
            raise ValueError(f"Unknown phase: {phase}")


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

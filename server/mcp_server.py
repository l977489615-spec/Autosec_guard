"""
MCP Server — AutoSec Guard
===========================
将 AutoSec Guard 的底层扫描能力封装为模型上下文协议 (Model Context Protocol) 工具，
使 LLM Agent 们能够通过标准化 API 调用车载漏洞验证能力，实现自主渗透决策。

架构角色：
  AutoSec Flask API (server.py)
       ↓ HTTP REST
  MCP Server (this file, port 5003)
       ↓ Tool Call / Context
  Multi-Agent Orchestrator (agents/orchestrator.py)
       ↓ LLM Qwen API
  Agent 1 (侦察), Agent 2 (决策), Agent 3 (执行), Agent 4 (评估)

此 MCP Server 暴露以下工具：
  - scan_ports(target_ip) → 端口/服务列表
  - run_poc(poc_name, params) → PoC 执行结果
  - get_topology(target_ip) → 拓扑图分析
  - get_physical_state() → CAN 物理安全状态
  - check_safety(poc_name) → 是否允许执行
  - list_pocs(category?) → 可用 PoC 列表
"""

import os
import sys
import json
import logging
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

# 确保上级目录在 sys.path 中
SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SERVER_DIR)

from topology_scanner import TopologyAwareScanner
from physical_safety_monitor import get_or_create_engine

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s')

app = Flask(__name__)
CORS(app)

# 主 AutoSec Flask API 地址
AUTOSEC_API = os.environ.get("AUTOSEC_API", "http://localhost:5002")


# ──────────────────────────────────────────────
# MCP Tool Definitions (暴露给 LLM Agent)
# ──────────────────────────────────────────────

MCP_TOOLS = [
    {
        "name": "scan_ports",
        "description": (
            "Scan a target vehicle IP for open ports and running services. "
            "Returns a list of open ports and service names (SSH, SOME/IP, DoIP, etc.)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_ip": {"type": "string", "description": "IP address of the target ECU or IVI system"},
                "timeout": {"type": "number", "description": "Timeout in seconds per port (default: 2.0)"},
            },
            "required": ["target_ip"],
        },
    },
    {
        "name": "run_poc",
        "description": (
            "Execute a specific PoC (Proof of Concept) vulnerability verification module. "
            "Returns whether the target is vulnerable, and exploit evidence if successful. "
            "Dangerous PoCs (ECUReset, CAN injection) will be blocked if the vehicle is in motion."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "poc_name": {"type": "string", "description": "PoC script name or path, e.g. '10_SSH_Weak_Creds.py'"},
                "params": {
                    "type": "object",
                    "description": "PoC parameters dict (target_ip, target_port, interface, etc.)",
                },
            },
            "required": ["poc_name", "params"],
        },
    },
    {
        "name": "get_topology",
        "description": (
            "Perform a topology-aware network scan to detect security gateways (SEC-GW), "
            "enumerate ECU nodes, and recommend the best attack vector path "
            "('direct', 'lateral_wifi', or 'obd_tunnel')."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_ip": {"type": "string", "description": "Target vehicle IP"},
            },
            "required": ["target_ip"],
        },
    },
    {
        "name": "get_adaptive_context",
        "description": (
            "Get the adaptive scanning context for a target IVI system. "
            "Returns detected services, recommended PoC subset, IVI load status, "
            "authentication types found (SSH/HTTP/UDS), and recommended test strategies per service. "
            "Use this before deciding which PoCs to run."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_ip": {"type": "string", "description": "Target IVI or ECU IP address"},
                "open_ports": {
                    "type": "array",
                    "items": {"type": "number"},
                    "description": "List of already-discovered open ports (from scan_ports result)",
                },
            },
            "required": ["target_ip"],
        },
    },
    {
        "name": "check_safety",
        "description": "Check whether a PoC module is safe and recommended based on the adaptive context for this target. Returns should_run=True/False and suggested strategy.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_ip": {"type": "string", "description": "Target IP"},
                "poc_name": {"type": "string", "description": "Name of the PoC to check"},
                "protocol": {"type": "string", "description": "Protocol (ssh/http/uds/can/someip)"},
            },
            "required": ["target_ip", "poc_name"],
        },
    },
    {
        "name": "list_pocs",
        "description": "List all available PoC vulnerability modules, optionally filtered by category.",
        "parameters": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Filter by category: reconnaissance, network, canbus, wireless, application, advanced",
                },
            },
            "required": [],
        },
    },
]


# ──────────────────────────────────────────────
# MCP REST API 端点
# ──────────────────────────────────────────────

@app.route("/mcp/tools", methods=["GET"])
def list_tools():
    """返回所有可用 MCP 工具描述（Agent 注册时调用）"""
    return jsonify({"tools": MCP_TOOLS})


@app.route("/mcp/call", methods=["POST"])
def call_tool():
    """
    Agent 调用 MCP 工具的统一入口
    请求体: { "tool": "tool_name", "params": {...} }
    """
    data = request.json or {}
    tool = data.get("tool")
    params = data.get("params", {})

    if not tool:
        return jsonify({"error": "Missing 'tool' field"}), 400

    logger.info(f"[MCP] Tool call: {tool}({json.dumps(params, ensure_ascii=False)[:120]})")

    try:
        if tool == "scan_ports":
            result = _tool_scan_ports(params)
        elif tool == "run_poc":
            result = _tool_run_poc(params)
        elif tool == "get_topology":
            result = _tool_get_topology(params)
        elif tool == "get_adaptive_context":
            result = _tool_get_adaptive_context(params)
        elif tool == "check_safety":
            result = _tool_check_safety(params)
        elif tool == "list_pocs":
            result = _tool_list_pocs(params)
        else:
            return jsonify({"error": f"Unknown tool: {tool}"}), 404

        return jsonify({"tool": tool, "result": result})

    except Exception as e:
        logger.error(f"[MCP] Tool execution error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/mcp/schema", methods=["GET"])
def get_schema():
    """返回 MCP 适配器 Schema，供 Claude/Qwen MCP 客户端自动注册"""
    return jsonify({
        "name": "autosec-guard",
        "version": "1.0.0",
        "description": "AutoSec Guard ICV Vulnerability Scanner — MCP Tool Server",
        "tools": MCP_TOOLS,
        "endpoint": "/mcp/call",
    })


# ──────────────────────────────────────────────
# Tool Implementations
# ──────────────────────────────────────────────

def _tool_scan_ports(params: dict) -> dict:
    target_ip = params.get("target_ip")
    timeout = float(params.get("timeout", 2.0))
    if not target_ip:
        raise ValueError("target_ip is required")

    scanner = TopologyAwareScanner(target_ip, timeout=timeout)
    scanner._scan_ports()  # 仅执行端口扫描步骤

    nodes = scanner.topo_map.nodes
    open_ports = nodes[0].open_ports if nodes else []
    services = nodes[0].services if nodes else []

    return {
        "target_ip": target_ip,
        "open_ports": open_ports,
        "services": services,
        "port_count": len(open_ports),
    }


def _tool_run_poc(params: dict) -> dict:
    poc_name = params.get("poc_name")
    poc_params = params.get("params", {})
    if not poc_name:
        raise ValueError("poc_name is required")

    # 调用主 AutoSec API
    try:
        resp = requests.post(
            f"{AUTOSEC_API}/api/run_poc",
            json={"poc_file": poc_name, "params": poc_params},
            timeout=60,
        )
        if resp.ok:
            data = resp.json()
            return {
                "blocked": False,
                "vulnerable": data.get("vulnerable"),
                "evidence": data.get("evidence", ""),
                "execution_time": data.get("execution_time"),
                "logs": data.get("logs", []),
            }
        else:
            return {"blocked": False, "error": f"API returned {resp.status_code}", "details": resp.text}
    except requests.exceptions.ConnectionError:
        raise ConnectionError(f"Cannot connect to AutoSec API at {AUTOSEC_API}")


def _tool_get_topology(params: dict) -> dict:
    target_ip = params.get("target_ip")
    if not target_ip:
        raise ValueError("target_ip is required")

    scanner = TopologyAwareScanner(target_ip, timeout=3.0)
    topo = scanner.scan()
    return topo.to_dict()


def _tool_get_adaptive_context(params: dict) -> dict:
    target_ip = params.get("target_ip")
    if not target_ip:
        raise ValueError("target_ip is required")
    open_ports = params.get("open_ports") or []
    if isinstance(open_ports, str):
        open_ports = [int(p) for p in open_ports.split(",") if p.strip().isdigit()]

    engine = get_or_create_engine(target_ip)
    summary = engine.initialize(open_ports)
    return summary


def _tool_check_safety(params: dict) -> dict:
    target_ip = params.get("target_ip", "")
    poc_name = params.get("poc_name", "")
    protocol = params.get("protocol", "")

    if not target_ip:
        return {"should_run": True, "strategy": "default", "reason": "No context available"}

    engine = get_or_create_engine(target_ip)
    skip, reason = engine.should_skip_poc(poc_name, protocol)
    strategy = engine.get_adaptive_strategy_for(protocol) if protocol else "default"
    interval = engine.get_throttle_delay()
    return {
        "should_run": not skip,
        "strategy": strategy,
        "recommended_interval_s": interval,
        "reason": reason or "Context check passed — proceed with recommended strategy",
    }


def _tool_list_pocs(params: dict) -> dict:
    category_filter = params.get("category")
    try:
        resp = requests.get(f"{AUTOSEC_API}/api/list_pocs", timeout=10)
        if resp.ok:
            pocs = resp.json().get("pocs", [])
            if category_filter:
                pocs = [p for p in pocs if category_filter.lower() in p.get("category", "").lower()]
            return {"pocs": pocs, "count": len(pocs)}
        return {"pocs": [], "count": 0, "error": f"API {resp.status_code}"}
    except Exception as e:
        return {"pocs": [], "count": 0, "error": str(e)}


# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("MCP_PORT", 5003))
    logger.info(f"[MCP Server] 启动 AutoSec Guard MCP Server，端口={port}")
    logger.info(f"[MCP Server] 主 API 地址: {AUTOSEC_API}")
    logger.info(f"[MCP Server] 工具列表: GET /mcp/tools")
    logger.info(f"[MCP Server] 工具调用: POST /mcp/call")
    app.run(host="0.0.0.0", port=port, debug=False)

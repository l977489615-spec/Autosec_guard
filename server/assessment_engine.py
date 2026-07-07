from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple


# ──────────────────────────────────────────────
# 默认规则与权重（可被外置配置文件覆盖）
# 对应专利：严重等级到风险评分的映射、判级规则、加固动作与风险下降分档均为“可配置项”
# ──────────────────────────────────────────────
DEFAULT_DOMAIN_RULES: List[Tuple[str, Dict[str, str]]] = [
    ("adb", {"domain": "ivi", "entry": "ADB", "capability": "remote_shell", "impact": "ivi_compromise"}),
    ("ssh", {"domain": "ivi", "entry": "SSH", "capability": "privileged_access", "impact": "ivi_compromise"}),
    ("telnet", {"domain": "ivi", "entry": "Telnet", "capability": "privileged_access", "impact": "ivi_compromise"}),
    ("mqtt", {"domain": "telematics", "entry": "MQTT", "capability": "broker_access", "impact": "backend_pivot"}),
    ("http", {"domain": "web", "entry": "HTTP", "capability": "service_execution", "impact": "ivi_compromise"}),
    ("rtsp", {"domain": "media", "entry": "RTSP", "capability": "media_control", "impact": "driver_distraction"}),
    ("dlna", {"domain": "media", "entry": "DLNA", "capability": "media_control", "impact": "driver_distraction"}),
    ("airplay", {"domain": "media", "entry": "AirPlay", "capability": "media_control", "impact": "driver_distraction"}),
    ("carplay", {"domain": "media", "entry": "CarPlay", "capability": "media_control", "impact": "driver_distraction"}),
    ("wifi", {"domain": "wireless", "entry": "Wi-Fi", "capability": "wireless_pivot", "impact": "lateral_movement"}),
    ("bluetooth", {"domain": "bluetooth", "entry": "Bluetooth", "capability": "adjacent_access", "impact": "driver_distraction"}),
    ("bt", {"domain": "bluetooth", "entry": "Bluetooth", "capability": "adjacent_access", "impact": "driver_distraction"}),
    ("ble", {"domain": "bluetooth", "entry": "BLE", "capability": "adjacent_access", "impact": "driver_distraction"}),
    ("can", {"domain": "canbus", "entry": "CAN", "capability": "bus_access", "impact": "ecu_disruption"}),
    ("uds", {"domain": "canbus", "entry": "UDS", "capability": "diagnostic_access", "impact": "ecu_disruption"}),
    ("obd", {"domain": "diagnostics", "entry": "OBD", "capability": "diagnostic_access", "impact": "ecu_disruption"}),
    ("doip", {"domain": "diagnostics", "entry": "DoIP", "capability": "diagnostic_access", "impact": "ecu_disruption"}),
    ("ota", {"domain": "firmware", "entry": "OTA", "capability": "firmware_tampering", "impact": "persistent_compromise"}),
    ("firmware", {"domain": "firmware", "entry": "Firmware", "capability": "firmware_tampering", "impact": "persistent_compromise"}),
    ("usb", {"domain": "physical", "entry": "USB", "capability": "local_code_exec", "impact": "persistent_compromise"}),
    ("gps", {"domain": "sensors", "entry": "GPS", "capability": "sensor_spoofing", "impact": "navigation_manipulation"}),
    ("tpms", {"domain": "sensors", "entry": "TPMS", "capability": "sensor_spoofing", "impact": "driver_distraction"}),
    ("v2x", {"domain": "telematics", "entry": "V2X", "capability": "message_injection", "impact": "traffic_manipulation"}),
]

DEFAULT_DOMAIN_ACTIONS: Dict[str, Tuple[str, str]] = {
    "ivi": ("disable_debug_services", "关闭调试端口并强制 SSH 密钥认证"),
    "wireless": ("segment_wireless", "隔离车载 Wi-Fi 与诊断域网络"),
    "bluetooth": ("restrict_pairing", "限制蓝牙配对窗口并启用设备白名单"),
    "canbus": ("enforce_uds_auth", "启用 UDS 安全访问和关键 ECU 白名单"),
    "firmware": ("signed_updates", "启用固件签名校验与防回滚保护"),
    "telematics": ("broker_hardening", "收敛云控接口并加强消息鉴权"),
    "media": ("service_minimization", "关闭未授权媒体服务并隔离投屏能力"),
    "physical": ("usb_guard", "限制 USB 调试与更新包导入"),
    "sensors": ("sensor_validation", "增加传感器消息校验与异常告警"),
    "web": ("harden_web", "关闭弱配置 Web 服务并启用访问控制"),
    "diagnostics": ("diag_isolation", "隔离诊断域并限制本地维护接口"),
}

IMPACT_LABELS: Dict[str, str] = {
    "ecu_disruption": "ECU 功能扰动",
    "driver_distraction": "驾驶员干扰",
    "persistent_compromise": "持久化控制风险",
    "navigation_manipulation": "导航欺骗",
    "traffic_manipulation": "交通信息操控",
    "ivi_compromise": "IVI 控制权获取",
    "backend_pivot": "T-Box / 云控侧横向移动",
    "lateral_movement": "车内横向移动",
}

DEFAULT_SEVERITY_SCORES: Dict[str, int] = {
    "critical": 95, "high": 78, "medium": 55, "low": 25, "info": 10,
}
DEFAULT_SEVERITY_SCORE_FALLBACK = 45

DEFAULT_GENERIC_RULE: Dict[str, str] = {
    "domain": "generic", "entry": "Network", "capability": "service_access", "impact": "lateral_movement",
}

# 判级规则（可配置）：触发危急/高级的攻击域集合、触发危急的物理影响、触发中级的漏洞数量阈值
DEFAULT_LEVEL_RULES: Dict[str, Any] = {
    "critical_domains": ["canbus"],
    "critical_impact_keyword": "ECU",
    "high_domains": ["wireless", "bluetooth", "firmware"],
    "medium_min_findings": 2,
}

# 风险下降分档（可配置）
DEFAULT_REDUCTION: Dict[str, Any] = {
    "high_domains": ["canbus", "firmware", "wireless"],
    "high_value": 18,
    "default_value": 12,
}

# ──────────────────────────────────────────────
# 多跳攻击图：跨漏洞可达性（转移）模型（可配置）
# 含义：攻击者获得某利用能力后，可据此横向到达的下游攻击域集合。
# 用于在共享语义节点之间建立 pivots_to 边，从而推导跨多个漏洞的攻击链。
# ──────────────────────────────────────────────
DEFAULT_PIVOT_RULES: Dict[str, List[str]] = {
    "remote_shell": ["canbus", "diagnostics", "sensors", "telematics", "firmware"],
    "privileged_access": ["canbus", "diagnostics", "sensors", "firmware"],
    "service_execution": ["ivi", "canbus", "diagnostics"],
    "wireless_pivot": ["ivi", "canbus"],
    "adjacent_access": ["ivi"],
    "media_control": ["ivi"],
    "broker_access": ["telematics", "ivi"],
    "local_code_exec": ["ivi", "firmware"],
    "firmware_tampering": ["ivi", "canbus"],
    "bus_access": [],
    "diagnostic_access": [],
    "message_injection": [],
    "sensor_spoofing": [],
}

# 外部可达入口域：攻击者无需前置即可初始接触的攻击域
DEFAULT_EXTERNAL_ENTRY_DOMAINS: List[str] = [
    "web", "wireless", "bluetooth", "physical", "telematics", "media", "ivi",
]

# 位于安全网关之后的车内域；存在 SEC-GW 且推荐向量为 direct 时，通往这些域的转移边被门控
DEFAULT_GATEWAY_PROTECTED_DOMAINS: List[str] = ["canbus", "diagnostics"]

# 到达即视为产生物理/功能安全后果的物理影响
DEFAULT_PHYSICAL_IMPACTS: List[str] = [
    "ecu_disruption", "persistent_compromise", "navigation_manipulation", "traffic_manipulation",
]

# 多跳评分参数（可配置）
DEFAULT_MULTIHOP_SCORING: Dict[str, Any] = {
    "hop_bonus": 5,       # 每多一跳的风险加成
    "gated_penalty": 8,   # 每经过一条被网关门控的转移边的惩罚
    "max_depth": 8,       # 路径最大漏洞跳数，防止组合爆炸
}

# 在线探测规划器权重与代价（可配置）
DEFAULT_EXPLORATION_PLANNER: Dict[str, Any] = {
    "w_reach": 1.0,
    "w_info": 0.6,
    "w_cost": 0.4,
    "w_risk": 0.5,
    "cost_by_profile": {
        "network": 1, "advanced_network": 2, "application": 2,
        "usb_adb": 3, "local_artifact": 2, "wireless": 4, "canbus": 5, "bluetooth": 4,
    },
    "risk_by_destructive_level": {
        "Safe": 0, "Probe": 1, "Disruptive": 3, "restart": 4, "dataloss": 5, "brick": 6,
    },
}


# ──────────────────────────────────────────────
# 配置加载：运行时可通过外置 JSON 文件覆盖上述默认值
# 文件路径优先取环境变量 ASSESSMENT_CONFIG，否则取模块同级 assessment_config.json
# ──────────────────────────────────────────────
_CONFIG_CACHE: Dict[str, Any] | None = None


def _config_path() -> Path:
    env_path = os.environ.get("ASSESSMENT_CONFIG", "").strip()
    if env_path:
        return Path(env_path)
    return Path(__file__).resolve().parent / "assessment_config.json"


def load_config(force_reload: bool = False) -> Dict[str, Any]:
    """加载评估配置，外置文件存在时覆盖默认值；否则全部回退默认。"""
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None and not force_reload:
        return _CONFIG_CACHE

    cfg: Dict[str, Any] = {
        "domain_rules": [list(item) for item in DEFAULT_DOMAIN_RULES],
        "domain_actions": {k: list(v) for k, v in DEFAULT_DOMAIN_ACTIONS.items()},
        "severity_scores": dict(DEFAULT_SEVERITY_SCORES),
        "severity_score_fallback": DEFAULT_SEVERITY_SCORE_FALLBACK,
        "generic_rule": dict(DEFAULT_GENERIC_RULE),
        "level_rules": dict(DEFAULT_LEVEL_RULES),
        "reduction": dict(DEFAULT_REDUCTION),
        "pivot_rules": {k: list(v) for k, v in DEFAULT_PIVOT_RULES.items()},
        "external_entry_domains": list(DEFAULT_EXTERNAL_ENTRY_DOMAINS),
        "gateway_protected_domains": list(DEFAULT_GATEWAY_PROTECTED_DOMAINS),
        "physical_impacts": list(DEFAULT_PHYSICAL_IMPACTS),
        "multihop_scoring": dict(DEFAULT_MULTIHOP_SCORING),
        "exploration_planner": dict(DEFAULT_EXPLORATION_PLANNER),
    }

    path = _config_path()
    try:
        if path.exists():
            override = json.loads(path.read_text(encoding="utf-8"))
            for key, value in (override or {}).items():
                if key in cfg and isinstance(cfg[key], dict) and isinstance(value, dict):
                    cfg[key].update(value)
                else:
                    cfg[key] = value
    except Exception:
        # 配置文件损坏时静默回退默认，保证评估流程不中断
        pass

    _CONFIG_CACHE = cfg
    return cfg


def _domain_rules() -> List[Tuple[str, Dict[str, str]]]:
    return [(str(kw), dict(rule)) for kw, rule in load_config()["domain_rules"]]


# 兼容旧引用：保留模块级常量名（指向默认值）
DOMAIN_RULES = DEFAULT_DOMAIN_RULES
DOMAIN_ACTIONS = DEFAULT_DOMAIN_ACTIONS


def _normalize_finding_name(finding: dict) -> str:
    return (finding.get("name") or finding.get("pocId") or "Unknown").lower()


def _tokenize(text: str) -> set:
    """将名称切成词元集合：按非字母数字分隔，并在字母与数字交界处断开。

    用于关键词匹配，避免朴素子串误命中（例如关键词 'can' 不应命中 'scan'/'tcp_port_scan'）。
    """
    import re as _re
    text = (text or "").lower()
    text = _re.sub(r"([a-z])([0-9])", r"\1 \2", text)
    text = _re.sub(r"([0-9])([a-z])", r"\1 \2", text)
    return {tok for tok in _re.split(r"[^a-z0-9]+", text) if tok}


def match_domain_rule(text: str, cfg: Dict[str, Any] | None = None) -> Dict[str, str]:
    """按词元匹配领域规则；命中返回对应四元组，未命中返回通用回退四元组。"""
    cfg = cfg or load_config()
    tokens = _tokenize(text)
    for keyword, rule in cfg["domain_rules"]:
        kw = str(keyword).lower()
        if kw in tokens:
            return dict(rule)
    return dict(cfg["generic_rule"])


def classify_finding(finding: dict) -> Dict[str, str]:
    return match_domain_rule(_normalize_finding_name(finding))


def _severity_score(severity: str) -> int:
    cfg = load_config()
    mapping = cfg["severity_scores"]
    return int(mapping.get((severity or "medium").lower(), cfg["severity_score_fallback"]))


def _new_finding_nodes_edges_path(finding: dict, index: int) -> Tuple[List[dict], List[dict], dict]:
    """为单个漏洞构建四类节点、三条有向边与一条攻击路径。供全量与增量构建复用。"""
    rule = classify_finding(finding)
    severity = finding.get("severity") or "High"
    evidence = finding.get("details") or finding.get("description") or ""
    entry_id = f"entry_{index}"
    vuln_id = f"vuln_{index}"
    capability_id = f"cap_{index}"
    impact_id = f"impact_{index}"

    nodes = [
        {"id": entry_id, "type": "entry", "label": rule["entry"], "severity": severity, "domain": rule["domain"]},
        {"id": vuln_id, "type": "vulnerability", "label": finding.get("name") or finding.get("pocId") or f"Finding {index}", "severity": severity, "domain": rule["domain"], "evidence": evidence},
        {"id": capability_id, "type": "capability", "label": rule["capability"].replace("_", " ").title(), "severity": severity, "domain": rule["domain"]},
        {"id": impact_id, "type": "impact", "label": IMPACT_LABELS.get(rule["impact"], rule["impact"]), "severity": severity, "domain": rule["domain"]},
    ]
    edges = [
        {"source": entry_id, "target": vuln_id, "relation": "exposes"},
        {"source": vuln_id, "target": capability_id, "relation": "enables"},
        {"source": capability_id, "target": impact_id, "relation": "leads_to"},
    ]
    path = {
        "id": f"path_{index}",
        "title": f"{rule['entry']} -> {finding.get('name') or finding.get('pocId')} -> {IMPACT_LABELS.get(rule['impact'], rule['impact'])}",
        "riskScore": _severity_score(severity),
        "physicalImpact": IMPACT_LABELS.get(rule["impact"], rule["impact"]),
        "nodes": [entry_id, vuln_id, capability_id, impact_id],
    }
    return nodes, edges, path


def generate_attack_graph(session: dict) -> dict:
    target_name = session.get("targetName") or "Vehicle Target"
    findings = [f for f in session.get("results", []) if f.get("vulnerable")]
    nodes: List[dict] = []
    edges: List[dict] = []
    paths: List[dict] = []

    if not findings:
        return {
            "nodes": [],
            "edges": [],
            "paths": [],
            "summary": f"{target_name} 当前未形成可确认攻击路径。",
        }

    for index, finding in enumerate(findings, start=1):
        f_nodes, f_edges, f_path = _new_finding_nodes_edges_path(finding, index)
        nodes.extend(f_nodes)
        edges.extend(f_edges)
        paths.append(f_path)

    paths.sort(key=lambda item: item["riskScore"], reverse=True)
    summary = f"{target_name} 形成 {len(paths)} 条可解释攻击路径，最高风险路径评分 {paths[0]['riskScore']}。"
    return {"nodes": nodes, "edges": edges, "paths": paths, "summary": summary}


def incremental_update_attack_graph(existing_graph: dict, new_findings: List[dict],
                                    target_name: str = "Vehicle Target") -> dict:
    """增量更新：将新增已确认漏洞构建的节点、边、攻击路径并入既有攻击路径图后重新排序。

    对应专利权利要求11/13与实施例七：当漏洞验证会话产生新增已确认漏洞时，仅对新增漏洞
    增量生成对应节点、边与路径并入既有图，而非整体重建。
    """
    existing_graph = existing_graph or {"nodes": [], "edges": [], "paths": []}
    nodes: List[dict] = list(existing_graph.get("nodes", []))
    edges: List[dict] = list(existing_graph.get("edges", []))
    paths: List[dict] = list(existing_graph.get("paths", []))

    # 既有图中已占用的最大序号，确保新增节点/路径标识不冲突
    used_indices = []
    for p in paths:
        try:
            used_indices.append(int(str(p.get("id", "path_0")).rsplit("_", 1)[-1]))
        except (ValueError, IndexError):
            continue
    start = (max(used_indices) + 1) if used_indices else 1

    # 已存在的漏洞节点标签集合，用于去重，避免重复并入同一漏洞
    existing_vuln_labels = {
        n.get("label") for n in nodes if n.get("type") == "vulnerability"
    }

    added = 0
    for offset, finding in enumerate([f for f in new_findings if f.get("vulnerable")]):
        label = finding.get("name") or finding.get("pocId")
        if label and label in existing_vuln_labels:
            continue
        f_nodes, f_edges, f_path = _new_finding_nodes_edges_path(finding, start + offset)
        nodes.extend(f_nodes)
        edges.extend(f_edges)
        paths.append(f_path)
        existing_vuln_labels.add(label)
        added += 1

    paths.sort(key=lambda item: item["riskScore"], reverse=True)
    if paths:
        summary = (f"{target_name} 形成 {len(paths)} 条可解释攻击路径"
                   f"（本次增量并入 {added} 条），最高风险路径评分 {paths[0]['riskScore']}。")
    else:
        summary = f"{target_name} 当前未形成可确认攻击路径。"
    return {"nodes": nodes, "edges": edges, "paths": paths, "summary": summary}


def generate_multihop_attack_graph(session: dict, topology: dict | None = None) -> dict:
    """构建跨漏洞多跳攻击图：语义去重节点 + 转移(pivots_to)边 + 多跳攻击链推导。

    与 generate_attack_graph（每漏洞独立四元链）不同，本函数对入口/能力/物理影响节点按语义
    去重共享，并依据可达性转移模型在“能力节点”与“另一攻击域入口节点”之间建立 pivots_to 边，
    从而推导出贯穿多个漏洞的攻击链（如 外部无线接入 -> IVI 控制 -> CAN 总线 -> ECU 功能扰动）。
    若提供拓扑信息且存在安全网关，则对通往网关后车内域的转移边进行门控并计入风险代价。
    """
    target_name = session.get("targetName") or "Vehicle Target"
    findings = [f for f in session.get("results", []) if f.get("vulnerable")]
    if not findings:
        return {"nodes": [], "edges": [], "paths": [], "summary": f"{target_name} 当前未形成可确认攻击路径。"}

    cfg = load_config()
    pivot_rules: Dict[str, List[str]] = cfg["pivot_rules"]
    external_domains = set(cfg["external_entry_domains"])
    gated_domains = set(cfg["gateway_protected_domains"])
    physical_impacts = set(cfg["physical_impacts"])
    scoring = cfg["multihop_scoring"]
    hop_bonus = int(scoring.get("hop_bonus", 5))
    gated_penalty = int(scoring.get("gated_penalty", 8))
    max_depth = int(scoring.get("max_depth", 8))

    # 网关门控判定：存在安全网关且推荐向量为 direct（被网关阻隔）时，通往车内域的转移边被门控
    topology = topology or session.get("topology") or {}
    gateway_blocks = bool(topology.get("has_security_gateway")) and \
        str(topology.get("recommended_attack_vector") or "direct") == "direct"

    nodes: Dict[str, dict] = {}
    edges: List[dict] = []
    edge_seen: set = set()
    # 邻接表：node_id -> [(目标node_id, 关系, 是否门控)]
    adj: Dict[str, List[Tuple[str, str, bool]]] = {}
    # 域 -> 入口节点id；域 -> 该域内漏洞节点id列表
    domain_entry: Dict[str, str] = {}
    domain_vulns: Dict[str, List[str]] = {}
    vuln_meta: Dict[str, dict] = {}

    def _node(node_id: str, **attrs):
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, **attrs}
        return node_id

    def _edge(src: str, dst: str, relation: str, gated: bool = False):
        key = (src, dst, relation)
        if key in edge_seen:
            return
        edge_seen.add(key)
        edges.append({"source": src, "target": dst, "relation": relation, "gated": gated})
        adj.setdefault(src, []).append((dst, relation, gated))

    # 1) 构建共享语义节点与漏洞内边（exposes / enables / leads_to）
    for idx, finding in enumerate(findings, start=1):
        rule = classify_finding(finding)
        severity = finding.get("severity") or "High"
        evidence = finding.get("details") or finding.get("description") or ""
        domain, entry, capability, impact = rule["domain"], rule["entry"], rule["capability"], rule["impact"]

        entry_id = _node(f"entry::{domain}", type="entry", label=entry, domain=domain)
        domain_entry[domain] = entry_id
        vuln_id = _node(f"vuln::{idx}", type="vulnerability",
                        label=finding.get("name") or finding.get("pocId") or f"Finding {idx}",
                        severity=severity, domain=domain, evidence=evidence)
        cap_id = _node(f"cap::{capability}", type="capability",
                       label=capability.replace("_", " ").title(), capability=capability, domain=domain)
        impact_id = _node(f"impact::{impact}", type="impact",
                          label=IMPACT_LABELS.get(impact, impact), impact=impact, domain=domain)

        domain_vulns.setdefault(domain, []).append(vuln_id)
        vuln_meta[vuln_id] = {"severity": severity, "domain": domain, "capability": capability,
                              "impact": impact, "score": _severity_score(severity)}

        _edge(entry_id, vuln_id, "exposes")
        _edge(vuln_id, cap_id, "enables")
        _edge(cap_id, impact_id, "leads_to")

    # 2) 构建跨漏洞转移边（pivots_to）：能力节点 -> 可达下游域的入口节点
    present_domains = set(domain_entry.keys())
    for vuln_id, meta in vuln_meta.items():
        cap_id = f"cap::{meta['capability']}"
        for downstream in pivot_rules.get(meta["capability"], []):
            if downstream not in present_domains or downstream == meta["domain"]:
                continue
            gated = gateway_blocks and downstream in gated_domains
            _edge(cap_id, domain_entry[downstream], "pivots_to", gated=gated)

    # 3) 多跳路径枚举：从外部可达入口出发 DFS，沿边走到物理影响节点
    paths: List[dict] = []
    path_counter = [0]

    def _dfs(node_id: str, visited_vulns: Tuple[str, ...], chain: List[str],
             chain_vulns: List[str], gated_count: int):
        if len(chain_vulns) > max_depth:
            return
        node = nodes[node_id]
        ntype = node["type"]
        if ntype == "impact":
            # 到达物理影响节点，且链中至少含一个漏洞，记为一条攻击路径
            if chain_vulns:
                scores = [vuln_meta[v]["score"] for v in chain_vulns]
                hops = len(chain_vulns)
                risk = min(100, max(scores) + (hops - 1) * hop_bonus - gated_count * gated_penalty)
                risk = max(0, risk)
                last_impact = node.get("impact")
                path_counter[0] += 1
                first_vuln = vuln_meta[chain_vulns[0]]
                title = (f"{nodes[chain[0]]['label']} -> "
                         + " -> ".join(nodes[v]["label"] for v in chain_vulns)
                         + f" -> {node['label']}")
                paths.append({
                    "id": f"mhpath_{path_counter[0]}",
                    "title": title,
                    "riskScore": risk,
                    "hops": hops,
                    "physicalImpact": node["label"],
                    "reachesPhysical": last_impact in physical_impacts,
                    "gatedHops": gated_count,
                    "nodes": list(chain),
                })
            return
        for dst, relation, gated in adj.get(node_id, []):
            ng = gated_count + (1 if gated else 0)
            if dst.startswith("vuln::"):
                if dst in visited_vulns:
                    continue
                _dfs(dst, visited_vulns + (dst,), chain + [dst], chain_vulns + [dst], ng)
            else:
                # entry/cap/impact 节点不重复进入，避免环路
                if dst in chain:
                    continue
                _dfs(dst, visited_vulns, chain + [dst], chain_vulns, ng)

    for domain, entry_id in domain_entry.items():
        if domain in external_domains:
            _dfs(entry_id, tuple(), [entry_id], [], 0)

    paths.sort(key=lambda p: (p["reachesPhysical"], p["riskScore"], p["hops"]), reverse=True)

    kill_chains = [p for p in paths if p["hops"] >= 2 and p["reachesPhysical"]]
    if paths:
        summary = (f"{target_name} 共推导出 {len(paths)} 条攻击链，其中跨漏洞杀伤链 {len(kill_chains)} 条；"
                   f"最高风险链评分 {paths[0]['riskScore']}，最长链跨 {max(p['hops'] for p in paths)} 个漏洞。")
    else:
        summary = f"{target_name} 未推导出从外部入口到物理影响的攻击链。"

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "paths": paths,
        "killChainCount": len(kill_chains),
        "summary": summary,
    }


def incremental_update_multihop_attack_graph(prev_findings: List[dict], new_findings: List[dict],
                                             target_name: str = "Vehicle Target",
                                             topology: dict | None = None) -> dict:
    """多跳攻击图的增量更新：并入新增已确认漏洞后重新推导跨漏洞攻击链。

    对应专利三权利要求10/12与实施例七：当产生新增已确认漏洞时，仅对新增漏洞做增量并入
    （按漏洞标识去重，避免重复并入），再重新执行可达性转移建模、网关门控、跨漏洞攻击链
    推导与评分排序，得到更新后的攻击链集合。多跳图的转移边依赖全局攻击域集合，故转移建模
    与路径推导（对应步骤S4至S6）须在并入后整体重算，与权利要求“重新执行步骤S4至步骤S6”一致。
    """
    merged: List[dict] = []
    seen_labels: set = set()
    for f in list(prev_findings or []) + list(new_findings or []):
        if not f.get("vulnerable"):
            continue
        label = f.get("name") or f.get("pocId")
        if label is not None and label in seen_labels:
            continue
        seen_labels.add(label)
        merged.append(f)
    added = sum(
        1 for f in (new_findings or [])
        if f.get("vulnerable") and (f.get("name") or f.get("pocId")) not in
        {(g.get("name") or g.get("pocId")) for g in (prev_findings or []) if g.get("vulnerable")}
    )
    graph = generate_multihop_attack_graph(
        {"targetName": target_name, "results": merged, "topology": topology or {}}
    )
    graph["summary"] = graph.get("summary", "") + f"（本次增量并入 {added} 个漏洞）"
    return graph


def assess_physical_impact(session: dict) -> dict:
    findings = [f for f in session.get("results", []) if f.get("vulnerable")]
    if not findings:
        return {
            "operationalContext": "lab",
            "safetyLevel": "low",
            "impactDomains": [],
            "likelyEffects": [],
            "justification": "当前未检测到已确认漏洞，未形成明确的 Cyber-to-Physical 风险链路。",
        }

    rules = load_config()["level_rules"]
    crit_domains = set(rules.get("critical_domains", []))
    crit_kw = str(rules.get("critical_impact_keyword", "ECU"))
    high_domains = set(rules.get("high_domains", []))
    medium_min = int(rules.get("medium_min_findings", 2))

    domains: List[str] = []
    effects: List[str] = []
    max_score = 0
    for finding in findings:
        rule = classify_finding(finding)
        if rule["domain"] not in domains:
            domains.append(rule["domain"])
        effect = IMPACT_LABELS.get(rule["impact"], rule["impact"])
        if effect not in effects:
            effects.append(effect)
        max_score = max(max_score, _severity_score(finding.get("severity") or "High"))

    if crit_domains.intersection(domains) or any(crit_kw in effect for effect in effects):
        level = "critical"
    elif high_domains.intersection(domains):
        level = "high"
    elif len(findings) >= medium_min:
        level = "medium"
    else:
        level = "low"

    return {
        "operationalContext": "lab",
        "safetyLevel": level,
        "impactDomains": domains,
        "likelyEffects": effects,
        "justification": f"共确认 {len(findings)} 个可利用点，涉及 {', '.join(domains)} 攻击域，最高物理影响等级判定为 {level}。",
    }


def simulate_remediation(session: dict, attack_graph: dict | None = None) -> dict:
    graph = attack_graph or generate_attack_graph(session)
    findings = [f for f in session.get("results", []) if f.get("vulnerable")]
    before = min(100, max([path["riskScore"] for path in graph.get("paths", [])], default=session.get("riskScore", 0)))
    actions: List[dict] = []
    blocked_paths: List[str] = []

    cfg = load_config()
    domain_actions = {k: tuple(v) for k, v in cfg["domain_actions"].items()}
    reduction_cfg = cfg["reduction"]
    high_reduction_domains = set(reduction_cfg.get("high_domains", []))
    high_value = int(reduction_cfg.get("high_value", 18))
    default_value = int(reduction_cfg.get("default_value", 12))

    used_domains = []
    for finding in findings:
        domain = classify_finding(finding)["domain"]
        if domain in used_domains:
            continue
        used_domains.append(domain)
        action_id, description = domain_actions.get(domain, ("generic_hardening", "收敛暴露面并增加访问控制"))
        matching_nodes = [node["id"] for node in graph.get("nodes", []) if node.get("domain") == domain]
        affected_path_ids = [path["id"] for path in graph.get("paths", []) if any(node_id in path["nodes"] for node_id in matching_nodes)]
        blocked_paths.extend(affected_path_ids)
        reduction = high_value if domain in high_reduction_domains else default_value
        actions.append({
            "id": action_id,
            "title": description,
            "description": f"针对 {domain} 攻击域收敛入口并阻断横向移动。",
            "cost": "medium" if reduction >= high_value else "low",
            "estimatedRiskReduction": reduction,
            "affectsNodes": matching_nodes[:4],
        })

    total_reduction = sum(item["estimatedRiskReduction"] for item in actions)
    after = max(0, before - total_reduction)
    return {
        "beforeScore": before,
        "afterScore": after,
        "blockedPaths": sorted(set(blocked_paths)),
        "actions": actions,
    }


def build_structured_report(session: dict) -> dict:
    graph = generate_attack_graph(session)
    physical = assess_physical_impact(session)
    remediation = simulate_remediation(session, graph)
    # Using the new findings array if available, fallback to results
    findings = session.get("findings", []) or [f for f in session.get("results", []) if f.get("vulnerable")]

    return {
        "summary": {
            "targetName": session.get("targetName") or "Vehicle Target",
            "riskScore": session.get("riskScore", remediation["beforeScore"]),
            "attackPathCount": len(graph.get("paths", [])),
            "physicalImpact": physical["safetyLevel"],
        },
        "findings": [
            {
                "name": finding.get("name") or finding.get("pocId") or "Unknown Finding",
                "severity": finding.get("severity") or "High",
                "evidence": finding.get("details") or finding.get("description") or "",
                "domain": classify_finding(finding)["domain"],
            }
            for finding in findings
        ],
        "attackPaths": graph.get("paths", []),
        "physicalImpact": physical,
        "remediationPlan": remediation,
    }

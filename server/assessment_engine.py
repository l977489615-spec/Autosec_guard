from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple


DOMAIN_RULES: List[Tuple[str, Dict[str, str]]] = [
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
    ("ota", {"domain": "firmware", "entry": "OTA", "capability": "firmware_tampering", "impact": "persistent_compromise"}),
    ("firmware", {"domain": "firmware", "entry": "Firmware", "capability": "firmware_tampering", "impact": "persistent_compromise"}),
    ("usb", {"domain": "physical", "entry": "USB", "capability": "local_code_exec", "impact": "persistent_compromise"}),
    ("gps", {"domain": "sensors", "entry": "GPS", "capability": "sensor_spoofing", "impact": "navigation_manipulation"}),
    ("tpms", {"domain": "sensors", "entry": "TPMS", "capability": "sensor_spoofing", "impact": "driver_distraction"}),
    ("v2x", {"domain": "telematics", "entry": "V2X", "capability": "message_injection", "impact": "traffic_manipulation"}),
]

DOMAIN_ACTIONS = {
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

IMPACT_LABELS = {
    "ecu_disruption": "ECU 功能扰动",
    "driver_distraction": "驾驶员干扰",
    "persistent_compromise": "持久化控制风险",
    "navigation_manipulation": "导航欺骗",
    "traffic_manipulation": "交通信息操控",
    "ivi_compromise": "IVI 控制权获取",
    "backend_pivot": "T-Box / 云控侧横向移动",
    "lateral_movement": "车内横向移动",
}


def _normalize_finding_name(finding: dict) -> str:
    return (finding.get("name") or finding.get("pocId") or "Unknown").lower()


def classify_finding(finding: dict) -> Dict[str, str]:
    name = _normalize_finding_name(finding)
    for keyword, rule in DOMAIN_RULES:
        if keyword in name:
            return rule
    return {"domain": "generic", "entry": "Network", "capability": "service_access", "impact": "lateral_movement"}


def _severity_score(severity: str) -> int:
    mapping = {"critical": 95, "high": 78, "medium": 55, "low": 25, "info": 10}
    return mapping.get((severity or "medium").lower(), 45)


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
        rule = classify_finding(finding)
        severity = finding.get("severity") or "High"
        evidence = finding.get("details") or finding.get("description") or ""
        entry_id = f"entry_{index}"
        vuln_id = f"vuln_{index}"
        capability_id = f"cap_{index}"
        impact_id = f"impact_{index}"

        nodes.extend([
            {"id": entry_id, "type": "entry", "label": rule["entry"], "severity": severity, "domain": rule["domain"]},
            {"id": vuln_id, "type": "vulnerability", "label": finding.get("name") or finding.get("pocId") or f"Finding {index}", "severity": severity, "domain": rule["domain"], "evidence": evidence},
            {"id": capability_id, "type": "capability", "label": rule["capability"].replace("_", " ").title(), "severity": severity, "domain": rule["domain"]},
            {"id": impact_id, "type": "impact", "label": IMPACT_LABELS.get(rule["impact"], rule["impact"]), "severity": severity, "domain": rule["domain"]},
        ])
        edges.extend([
            {"source": entry_id, "target": vuln_id, "relation": "exposes"},
            {"source": vuln_id, "target": capability_id, "relation": "enables"},
            {"source": capability_id, "target": impact_id, "relation": "leads_to"},
        ])
        paths.append({
            "id": f"path_{index}",
            "title": f"{rule['entry']} -> {finding.get('name') or finding.get('pocId')} -> {IMPACT_LABELS.get(rule['impact'], rule['impact'])}",
            "riskScore": _severity_score(severity),
            "physicalImpact": IMPACT_LABELS.get(rule["impact"], rule["impact"]),
            "nodes": [entry_id, vuln_id, capability_id, impact_id],
        })

    paths.sort(key=lambda item: item["riskScore"], reverse=True)
    summary = f"{target_name} 形成 {len(paths)} 条可解释攻击路径，最高风险路径评分 {paths[0]['riskScore']}。"
    return {"nodes": nodes, "edges": edges, "paths": paths, "summary": summary}


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

    domains = []
    effects = []
    max_score = 0
    for finding in findings:
        rule = classify_finding(finding)
        if rule["domain"] not in domains:
            domains.append(rule["domain"])
        effect = IMPACT_LABELS.get(rule["impact"], rule["impact"])
        if effect not in effects:
            effects.append(effect)
        max_score = max(max_score, _severity_score(finding.get("severity") or "High"))

    if "canbus" in domains or any("ECU" in effect for effect in effects):
        level = "critical"
    elif "wireless" in domains or "bluetooth" in domains or "firmware" in domains:
        level = "high"
    elif len(findings) >= 2:
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

    used_domains = []
    for finding in findings:
        domain = classify_finding(finding)["domain"]
        if domain in used_domains:
            continue
        used_domains.append(domain)
        action_id, description = DOMAIN_ACTIONS.get(domain, ("generic_hardening", "收敛暴露面并增加访问控制"))
        matching_nodes = [node["id"] for node in graph.get("nodes", []) if node.get("domain") == domain]
        affected_path_ids = [path["id"] for path in graph.get("paths", []) if any(node_id in path["nodes"] for node_id in matching_nodes)]
        blocked_paths.extend(affected_path_ids)
        reduction = 18 if domain in {"canbus", "firmware", "wireless"} else 12
        actions.append({
            "id": action_id,
            "title": description,
            "description": f"针对 {domain} 攻击域收敛入口并阻断横向移动。",
            "cost": "medium" if reduction >= 18 else "low",
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

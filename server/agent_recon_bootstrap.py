"""Agent 侦察增强：对齐 Global candidate_ports、复用 scan_results、启发式攻击计划回退。"""
from __future__ import annotations

import re
import socket
from typing import Any

# 与 lab/experiment_config 中 candidate_ports 默认集一致
DEFAULT_CANDIDATE_PORTS = [
    21, 22, 23, 80, 443, 554, 1883, 502, 3804, 5555, 5556, 6666, 6667,
    7000, 7777, 8000, 8080, 8443, 8888, 9090, 9527, 9999, 13400, 30490, 19090,
]

PORT_SERVICE_LABELS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    80: "http",
    443: "https",
    554: "rtsp",
    1883: "mqtt",
    502: "modbus",
    5555: "adb",
    7000: "carplay",
    8000: "qnx",
    8080: "http-diag",
    8443: "https-diag",
    13400: "doip",
    30490: "someip",
    1900: "upnp",
}

PORT_POC_HEURISTIC: dict[int, str] = {
    21: "network/08_FTP_Anonymous.py",
    22: "network/03_SSH_Service.py",
    23: "network/06_Telnet_Service.py",
    80: "reconnaissance/08_HTTP_Service_Enum.py",
    443: "network/20_HTTPS_No_Cert_Pin.py",
    554: "network/11_RTSP_Log_Leak.py",
    1883: "network/09_MQTT_Unauth.py",
    5555: "network/02_ADB_Debug_Port.py",
    7000: "network/11_RTSP_Log_Leak.py",
    8000: "wireless/01_QNX_Qnet_File_Read.py",
    8080: "reconnaissance/08_HTTP_Service_Enum.py",
    13400: "network/14_SOMEIP_Service_Discovery.py",
    30490: "network/14_SOMEIP_Service_Discovery.py",
}

POC_FILENAME_PORT_HINTS: list[tuple[str, int]] = [
    ("FTP", 21),
    ("SSH", 22),
    ("Telnet", 23),
    ("ADB", 5555),
    ("MQTT", 1883),
    ("RTSP", 554),
    ("HTTP", 80),
    ("SOMEIP", 30490),
    ("DoIP", 13400),
    ("QNX", 8000),
    ("DBus", 0),
]


def parse_candidate_ports(value: str | list[int] | None) -> list[int]:
    if isinstance(value, list):
        ports = [int(p) for p in value if str(p).isdigit()]
        return sorted(set(ports)) if ports else list(DEFAULT_CANDIDATE_PORTS)
    if not value or not str(value).strip():
        return list(DEFAULT_CANDIDATE_PORTS)
    ports: list[int] = []
    for part in re.split(r"[,;\s]+", str(value).strip()):
        part = part.strip()
        if part.isdigit():
            ports.append(int(part))
    return sorted(set(ports)) if ports else list(DEFAULT_CANDIDATE_PORTS)


def _probe_tcp_port(target_ip: str, port: int, timeout: float) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def enhanced_port_scan(target_ip: str, candidate_ports: list[int] | None = None, timeout: float = 1.5) -> dict[str, Any]:
    """与 Global TCP 扫描口径对齐的并行端口探测（不依赖 LLM）。"""
    import concurrent.futures

    ports = candidate_ports or list(DEFAULT_CANDIDATE_PORTS)
    open_ports: list[int] = []
    services: list[dict[str, Any]] = []

    def worker(port: int):
        if _probe_tcp_port(target_ip, port, timeout):
            label = PORT_SERVICE_LABELS.get(port, f"tcp/{port}")
            return port, label
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        for item in pool.map(worker, ports):
            if item:
                port, label = item
                open_ports.append(port)
                services.append({"port": port, "service": label, "source": "enhanced_port_scan"})

    open_ports.sort()
    return {
        "summary": f"增强端口扫描完成：{target_ip} 开放 {len(open_ports)} 个端口 {open_ports}",
        "open_ports": open_ports,
        "services": services,
        "topology": {"nodes": [{"ip": target_ip, "open_ports": open_ports, "services": services}]},
        "recon_sources": ["enhanced_port_scan"],
    }


def _ports_from_evidence(text: str) -> set[int]:
    found: set[int] = set()
    for match in re.finditer(r"\b(?:port|端口)[:\s]*(\d{2,5})\b", text, re.I):
        found.add(int(match.group(1)))
    for match in re.finditer(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})\b", text):
        found.add(int(match.group(2)))
    return found


def _ports_from_poc_file(poc_file: str) -> set[int]:
    found: set[int] = set()
    upper = (poc_file or "").upper()
    for token, port in POC_FILENAME_PORT_HINTS:
        if token in upper and port:
            found.add(port)
    return found


def build_global_recon_seed(scan_rows: list[dict] | None) -> dict[str, Any] | None:
    """从 Global scan_results 提取开放端口与已检出服务线索。"""
    if not scan_rows:
        return None
    open_ports: set[int] = set()
    services: list[dict[str, Any]] = []
    vuln_pocs: list[str] = []

    for row in scan_rows:
        if not isinstance(row, dict):
            continue
        evidence = str(row.get("evidence") or "")
        open_ports.update(_ports_from_evidence(evidence))
        poc_file = str(row.get("poc_file") or "")
        open_ports.update(_ports_from_poc_file(poc_file))
        if row.get("vulnerable") is True and poc_file:
            vuln_pocs.append(poc_file)
            for port in _ports_from_poc_file(poc_file):
                services.append({
                    "port": port,
                    "service": PORT_SERVICE_LABELS.get(port, "detected"),
                    "source": "global_scan_vuln",
                    "poc_file": poc_file,
                })

    if not open_ports and not vuln_pocs:
        return None

    merged_ports = sorted(open_ports)
    return {
        "summary": (
            f"已复用 Global 扫描结果：{len(merged_ports)} 个端口线索，"
            f"{len(vuln_pocs)} 条 vulnerable 记录"
        ),
        "open_ports": merged_ports,
        "services": services,
        "global_vulnerable_pocs": sorted(set(vuln_pocs)),
        "recon_sources": ["global_scan_results"],
    }


def merge_recon_results(*chunks: dict[str, Any] | None) -> dict[str, Any]:
    merged: dict[str, Any] = {
        "summary": "",
        "open_ports": [],
        "services": [],
        "topology": {},
        "adaptive_context": {},
        "recon_sources": [],
    }
    port_set: set[int] = set()
    service_seen: set[tuple[Any, ...]] = set()
    summaries: list[str] = []
    global_vulns: list[str] = []

    for chunk in chunks:
        if not isinstance(chunk, dict) or not chunk:
            continue
        summaries.append(str(chunk.get("summary") or "").strip())
        for port in chunk.get("open_ports") or []:
            try:
                port_set.add(int(port))
            except (TypeError, ValueError):
                continue
        for svc in chunk.get("services") or []:
            if isinstance(svc, dict):
                key = (svc.get("port"), svc.get("service"))
            else:
                key = (svc,)
            if key not in service_seen:
                service_seen.add(key)
                merged["services"].append(svc)
        if chunk.get("topology"):
            merged["topology"] = chunk["topology"]
        if chunk.get("adaptive_context"):
            merged["adaptive_context"].update(chunk["adaptive_context"])
        for src in chunk.get("recon_sources") or []:
            if src not in merged["recon_sources"]:
                merged["recon_sources"].append(src)
        global_vulns.extend(chunk.get("global_vulnerable_pocs") or [])

    merged["open_ports"] = sorted(port_set)
    merged["summary"] = " | ".join(s for s in summaries if s) or f"合并侦察：开放端口 {merged['open_ports']}"
    if global_vulns:
        merged["global_vulnerable_pocs"] = sorted(set(global_vulns))
    if merged["open_ports"] and not merged["topology"]:
        merged["topology"] = {"nodes": [{"open_ports": merged["open_ports"], "services": merged["services"]}]}
    return merged


def build_heuristic_attack_plan(
    open_ports: list[int],
    available_params: dict[str, str],
    global_vulnerable_pocs: list[str] | None = None,
) -> dict[str, Any]:
    """决策 LLM 失败时的规则化攻击计划（优先 Global 已检出 + 端口映射 PoC）。"""
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    step = 1
    target_ip = available_params.get("target_ip", "")

    for poc in global_vulnerable_pocs or []:
        if poc in seen or not poc.endswith(".py"):
            continue
        seen.add(poc)
        items.append({
            "step": step,
            "poc_name": poc,
            "parameters": {"target_ip": target_ip},
            "strategy": "direct_exploit",
            "reason": "Global 扫描已检出风险，Agent 定向复验",
        })
        step += 1

    for port in sorted(set(int(p) for p in open_ports)):
        poc = PORT_POC_HEURISTIC.get(port)
        if not poc or poc in seen:
            continue
        if "bluetooth" in poc.lower() and not available_params.get("bluetooth_mac"):
            continue
        if "canbus" in poc.lower() and not available_params.get("can_interface"):
            continue
        if "01_USB_ADB" in poc and not available_params.get("expected_usb_serial"):
            pass  # 网络 ADB 5555 不需要 USB serial
        seen.add(poc)
        items.append({
            "step": step,
            "poc_name": poc,
            "parameters": {"target_ip": target_ip, "port": port},
            "strategy": "direct_exploit",
            "reason": f"侦察发现开放端口 {port}，规则映射 PoC",
        })
        step += 1

    return {
        "items": items[:20],
        "item_count": min(len(items), 20),
        "summary": f"启发式攻击计划：{min(len(items), 20)} 步（含 Global 复验）",
        "parse_error": None,
        "plan_source": "heuristic_fallback",
    }

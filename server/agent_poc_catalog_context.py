"""为 Agent 决策阶段生成 PoC 元数据表与端口↔PoC 映射（对齐 poc_coverage.json）。"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from agent_recon_bootstrap import POC_FILENAME_PORT_HINTS, PORT_POC_HEURISTIC, PORT_SERVICE_LABELS

_SERVER_DIR = Path(__file__).resolve().parent
_POCS_ROOT = _SERVER_DIR / "pocs"

PROTOCOL_DEFAULT_PORTS: dict[str, list[int]] = {
    "ftp": [21],
    "ssh": [22],
    "telnet": [23],
    "http": [80, 8080, 8443],
    "https": [443, 8443],
    "mqtt": [1883],
    "rtsp": [554, 7000],
    "adb": [5555],
    "upnp": [1900],
    "someip": [30490],
    "doip": [13400],
    "modbus": [502],
    "bluetooth": [],
    "can": [],
}

_CATEGORY_ORDER = ("reconnaissance", "network", "application", "wireless", "canbus", "advanced")


def _listify(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [part.strip() for part in re.split(r"[,;|]", value) if part.strip()]
    return [str(value).strip()] if str(value).strip() else []


def _ports_for_poc_file(poc_file: str, protocol: str) -> list[int]:
    ports: set[int] = set()
    upper = (poc_file or "").upper()
    for token, port in POC_FILENAME_PORT_HINTS:
        if token in upper and port:
            ports.add(port)
    proto = str(protocol or "").lower().strip()
    for port in PROTOCOL_DEFAULT_PORTS.get(proto, []):
        ports.add(port)
    base = os.path.basename(poc_file or "")
    for port, mapped in PORT_POC_HEURISTIC.items():
        if mapped.endswith(base) or mapped == poc_file:
            ports.add(port)
    return sorted(ports)


def build_port_to_poc_map(pocs: list[dict[str, Any]]) -> dict[int, list[str]]:
    index: dict[int, list[str]] = {}
    for port, poc_file in sorted(PORT_POC_HEURISTIC.items()):
        index.setdefault(port, [])
        if poc_file not in index[port]:
            index[port].append(poc_file)
    for meta in pocs:
        poc_file = str(meta.get("poc_file") or "").strip()
        if not poc_file:
            continue
        for port in _ports_for_poc_file(poc_file, str(meta.get("protocol") or "")):
            index.setdefault(port, [])
            if poc_file not in index[port]:
                index[port].append(poc_file)
    for port in index:
        index[port] = sorted(index[port])
    return index


def load_poc_coverage_entries(coverage_path: str | Path | None = None) -> list[dict[str, Any]]:
    candidates: list[Path] = []
    if coverage_path:
        candidates.append(Path(coverage_path))
    candidates.extend([
        _SERVER_DIR.parent / "lab" / "evidence" / "poc_coverage.json",
        Path("lab/evidence/poc_coverage.json"),
    ])
    for path in candidates:
        if path.is_file():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                pocs = payload.get("pocs") or []
                if isinstance(pocs, list) and pocs:
                    return [p for p in pocs if isinstance(p, dict)]
            except Exception:
                continue
    return []


def _poc_allowed_by_resources(meta: dict[str, Any], available_params: dict[str, str]) -> bool:
    poc_file = str(meta.get("poc_file") or "").lower()
    if "bluetooth" in poc_file or "/bt_" in poc_file or "ble" in poc_file:
        if not str(available_params.get("bluetooth_mac") or "").strip():
            return False
    if "canbus" in poc_file or "/can" in poc_file or "isotp" in poc_file:
        if not str(available_params.get("can_interface") or "").strip():
            return False
    if "wireless" in poc_file or "wifi" in poc_file or "wpa" in poc_file:
        if not str(available_params.get("wifi_interface") or "").strip():
            return False
    if "01_usb_adb" in poc_file:
        if str(available_params.get("expected_usb_serial") or available_params.get("usb_device_serial") or "").strip():
            return True
        if str(available_params.get("local_usb_adb_attached") or "").strip().lower() in {"1", "true", "yes"}:
            return True
        return False
    return True


def filter_pocs_for_decision(
    pocs: list[dict[str, Any]],
    available_params: dict[str, str],
    open_ports: list[int] | None = None,
    global_vulnerable_pocs: list[str] | None = None,
    categories: tuple[str, ...] = ("reconnaissance", "network", "application"),
) -> list[dict[str, Any]]:
    open_set = {int(p) for p in (open_ports or [])}
    priority = set(global_vulnerable_pocs or [])
    selected: list[dict[str, Any]] = []
    for meta in pocs:
        poc_file = str(meta.get("poc_file") or "")
        if not poc_file:
            continue
        category = str(meta.get("category") or "").lower()
        if categories and category not in categories:
            continue
        if not _poc_allowed_by_resources(meta, available_params):
            continue
        if priority and poc_file in priority:
            selected.append(meta)
            continue
        if not open_set:
            selected.append(meta)
            continue
        poc_ports = _ports_for_poc_file(poc_file, str(meta.get("protocol") or ""))
        if category == "reconnaissance" or any(port in open_set for port in poc_ports):
            selected.append(meta)
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for meta in selected:
        key = meta.get("poc_file")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(meta)
    return deduped


def format_port_poc_mapping_section(
    port_map: dict[int, list[str]],
    open_ports: list[int] | None = None,
    global_vulnerable_pocs: list[str] | None = None,
) -> str:
    lines = ["【端口 ↔ PoC 映射（精简，执行时 poc_name 必须用完整路径）】"]
    focus_ports = sorted(set(open_ports or []) | set(port_map.keys()))
    if open_ports:
        focus_ports = sorted({int(p) for p in open_ports})
    shown = 0
    for port in focus_ports:
        pocs = port_map.get(port) or []
        if not pocs:
            continue
        label = PORT_SERVICE_LABELS.get(port, f"tcp/{port}")
        lines.append(f"  - 端口 {port} ({label}): " + ", ".join(pocs))
        shown += 1
    if global_vuln_list := sorted(set(global_vulnerable_pocs or [])):
        lines.append("【Global 扫描已检出（优先复验，建议全部纳入攻击计划）】")
        for poc in global_vuln_list:
            lines.append(f"  * {poc}")
    if shown == 0 and not global_vuln_list:
        lines.append("  （当前无开放端口映射；请结合 Global 已检出列表与下方元数据表）")
    return "\n".join(lines)


def format_poc_metadata_table(pocs: list[dict[str, Any]], max_rows: int = 96) -> str:
    lines = [
        "【PoC 元数据表（与 poc_coverage 对齐；poc_name 必须使用 poc_file 列原样）】",
        "poc_file | protocol | required_params | profiles | category",
        "---|---|---|---|---",
    ]
    for meta in pocs[:max_rows]:
        lines.append(
            " | ".join([
                str(meta.get("poc_file") or ""),
                str(meta.get("protocol") or ""),
                str(meta.get("required_params") or ""),
                str(meta.get("profiles") or ""),
                str(meta.get("category") or ""),
            ])
        )
    if len(pocs) > max_rows:
        lines.append(f"... 另有 {len(pocs) - max_rows} 条未展示，请对开放端口调用 list_pocs 补全")
    return "\n".join(lines)


def build_decision_poc_context(
    available_params: dict[str, str],
    open_ports: list[int] | None = None,
    global_vulnerable_pocs: list[str] | None = None,
    coverage_path: str | Path | None = None,
) -> str:
    all_pocs = load_poc_coverage_entries(coverage_path)
    if not all_pocs:
        return "【PoC 元数据】未加载 poc_coverage.json，请调用 list_pocs 获取清单。"
    filtered = filter_pocs_for_decision(
        all_pocs,
        available_params,
        open_ports=open_ports,
        global_vulnerable_pocs=global_vulnerable_pocs,
    )
    filtered.sort(key=lambda m: (
        _CATEGORY_ORDER.index(m.get("category"))
        if m.get("category") in _CATEGORY_ORDER
        else len(_CATEGORY_ORDER),
        str(m.get("poc_file") or ""),
    ))
    port_map = build_port_to_poc_map(all_pocs)
    sections = [
        format_port_poc_mapping_section(port_map, open_ports, global_vulnerable_pocs),
        "",
        format_poc_metadata_table(filtered),
    ]
    return "\n".join(sections)

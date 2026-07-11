"""为 Agent 决策阶段生成 PoC 元数据表与端口↔PoC 映射（默认读取运行时 server/pocs 目录）。"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from agent_recon_bootstrap import POC_FILENAME_PORT_HINTS, PORT_POC_HEURISTIC, PORT_SERVICE_LABELS
from poc_catalog import list_available_poc_names, resolve_poc_source
from poc_security import extract_poc_security_profile

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


def _attack_surface_for_category(category: str) -> str:
    mapping = {
        "network": "网络服务",
        "reconnaissance": "网络服务",
        "wireless": "无线/外设接口",
        "canbus": "CAN/UDS/OBD",
        "application": "车机APP/应用",
        "advanced": "固件/USB/OTA",
    }
    return mapping.get(category, "其他")


def load_runtime_poc_catalog_entries(pocs_dir: str | None = None) -> list[dict[str, Any]]:
    """Build PoC metadata from the live runtime catalog under server/pocs (no lab/ dependency)."""
    root = Path(pocs_dir) if pocs_dir else _POCS_ROOT
    entries: list[dict[str, Any]] = []
    for name in list_available_poc_names(str(root)):
        virtual_path, normalized, source = resolve_poc_source(str(root), name)
        if not virtual_path or not normalized or not source:
            continue
        profile = extract_poc_security_profile(virtual_path, source_text=source)
        category = normalized.replace("\\", "/").split("/", 1)[0]
        required_params = profile.get("required_params") or []
        if not isinstance(required_params, list):
            required_params = []
        profiles = profile.get("profiles") or profile.get("meta_profiles") or []
        if not isinstance(profiles, list):
            profiles = [profiles] if profiles else []
        severity = str(profile.get("severity") or "")
        destructive_level = str(profile.get("destructive_level") or "Safe")
        is_disruptive = bool(profile.get("is_disruptive"))
        entries.append({
            "poc_file": normalized,
            "display_id": profile.get("display_id") or Path(normalized).stem,
            "poc_name": profile.get("poc_name") or Path(normalized).stem,
            "category": category,
            "cve_id": profile.get("cve_id") or "",
            "severity": severity,
            "protocol": profile.get("protocol") or category,
            "target_os": profile.get("target_os") or ["all"],
            "required_params": ",".join(required_params),
            "profiles": profiles,
            "destructive_level": destructive_level,
            "is_disruptive": is_disruptive,
            "attack_surface": _attack_surface_for_category(category),
            "high_risk": severity in {"High", "Critical"} or is_disruptive,
            "requires_capabilities": profile.get("requires_capabilities") or [],
            "requires_any_capabilities": profile.get("requires_any_capabilities") or [],
            "excludes_capabilities": profile.get("excludes_capabilities") or [],
            "grants_on_confirmed": profile.get("grants_on_confirmed") or [],
        })
    return entries


def load_poc_catalog_entries(coverage_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Load PoC metadata for runtime services.

    Default: scan server/pocs directly.
    Optional coverage_path: explicit lab/experiment override only (not used in production paths).
    """
    if coverage_path:
        path = Path(coverage_path)
        if path.is_file():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                pocs = payload.get("pocs") or []
                if isinstance(pocs, list) and pocs:
                    return [p for p in pocs if isinstance(p, dict)]
            except Exception:
                pass
    return load_runtime_poc_catalog_entries()


def load_poc_coverage_entries(coverage_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Backward-compatible alias; prefer load_poc_catalog_entries."""
    return load_poc_catalog_entries(coverage_path)


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
        "【PoC 元数据表（运行时目录 server/pocs；poc_name 必须使用 poc_file 列原样）】",
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
    all_pocs = load_poc_catalog_entries(coverage_path)
    if not all_pocs:
        return "【PoC 元数据】运行时 PoC 目录为空，请调用 list_pocs 获取清单。"
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

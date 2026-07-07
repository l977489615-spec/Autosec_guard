"""PoC 元数据推断：补全原厂扩展脚本字段，并将 unknown 协议替换为可读值。"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

NEW_POC_TAG_PATTERN = re.compile(r'POC_TAG\s*=\s*["\'](.+?)["\']', re.S)
NEW_POC_FILE_PATTERN = re.compile(r"^poc(\d+)_")

# 原厂 IVI 扩展 PoC 精确元数据。早期位于 server/pocs/new/，现在按攻击面归入标准分类目录。
NEW_POC_KNOWN: dict[str, dict[str, Any]] = {
    "poc5_fileacl": {"protocol": "local", "severity": "Medium", "destructive_level": "Probe", "attack_surface": "系统配置/本地制品", "required_params": "expected_usb_serial", "profiles": ["local_artifact"]},
    "poc6_selinux": {"protocol": "local", "severity": "Medium", "destructive_level": "Probe", "attack_surface": "系统配置/本地制品", "required_params": "expected_usb_serial", "profiles": ["local_artifact"]},
    "poc7_stackchk": {"protocol": "local", "severity": "Medium", "destructive_level": "Probe", "attack_surface": "系统配置/本地制品", "required_params": "expected_usb_serial", "profiles": ["local_artifact"]},
    "poc8_vaspace": {"protocol": "local", "severity": "Medium", "destructive_level": "Probe", "attack_surface": "系统配置/本地制品", "required_params": "expected_usb_serial", "profiles": ["local_artifact"]},
    "poc10_http": {"protocol": "android", "severity": "Medium", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc11_debuggable": {"protocol": "android", "severity": "High", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc12_allowbackup": {"protocol": "android", "severity": "Medium", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc13_installask": {"protocol": "android", "severity": "Medium", "destructive_level": "Disruptive", "is_disruptive": True, "attack_surface": "固件/USB/OTA", "required_params": "expected_usb_serial", "profiles": ["usb_adb"]},
    "poc14_strandhogg": {"protocol": "android", "severity": "High", "destructive_level": "Probe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc15_activity_export": {"protocol": "android", "severity": "High", "destructive_level": "Probe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc16_service_export": {"protocol": "android", "severity": "High", "destructive_level": "Probe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc17_provider_export": {"protocol": "android", "severity": "High", "destructive_level": "Probe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc18_brordcast_export": {"protocol": "android", "severity": "High", "destructive_level": "Probe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc19_schemeurl_export": {"protocol": "android", "severity": "High", "destructive_level": "Probe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc20_libupnp": {"protocol": "upnp", "severity": "High", "destructive_level": "Probe", "attack_surface": "网络服务", "required_params": "target_ip", "profiles": ["network"]},
    "poc21_libavformat_export": {"protocol": "http", "severity": "Critical", "destructive_level": "Probe", "attack_surface": "第三方组件/高级漏洞", "required_params": "target_ip", "profiles": ["advanced_network"]},
    "poc22_libavformat_export2": {"protocol": "http", "severity": "Critical", "destructive_level": "Probe", "attack_surface": "第三方组件/高级漏洞", "required_params": "target_ip", "profiles": ["advanced_network"]},
    "poc23_libpng_export": {"protocol": "native", "severity": "High", "destructive_level": "Probe", "attack_surface": "第三方组件/高级漏洞", "required_params": "expected_usb_serial", "profiles": ["local_artifact"]},
    "poc24_openssl_export": {"protocol": "tls", "severity": "High", "destructive_level": "Probe", "attack_surface": "第三方组件/高级漏洞", "required_params": "expected_usb_serial", "profiles": ["local_artifact"]},
    "poc25_access_sdcard": {"protocol": "android", "severity": "Medium", "destructive_level": "Probe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc26_webview_java": {"protocol": "android", "severity": "High", "destructive_level": "Probe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc27_webview_rce": {"protocol": "android", "severity": "Critical", "destructive_level": "Probe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc28_webview_file": {"protocol": "android", "severity": "High", "destructive_level": "Probe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc29_openfile_anyrw": {"protocol": "android", "severity": "High", "destructive_level": "Probe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc30_openfile_anyw": {"protocol": "android", "severity": "High", "destructive_level": "Probe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc31_sharedprefs_anyr": {"protocol": "android", "severity": "High", "destructive_level": "Probe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc32_sharedprefs_anyw": {"protocol": "android", "severity": "High", "destructive_level": "Probe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc33_weakaes": {"protocol": "crypto", "severity": "Medium", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc34_pseudo_rand": {"protocol": "crypto", "severity": "Medium", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc35_bydlog": {"protocol": "local", "severity": "Low", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc36_bydtraffic_hijack": {"protocol": "can", "severity": "High", "destructive_level": "Medium", "attack_surface": "CAN/UDS/OBD", "required_params": "can_interface", "profiles": ["can_extended"]},
    "poc37_usb_inject": {"protocol": "usb", "severity": "High", "destructive_level": "Disruptive", "is_disruptive": True, "attack_surface": "固件/USB/OTA", "required_params": "expected_usb_serial", "profiles": ["usb_adb"]},
    "poc38_db_export": {"protocol": "android", "severity": "High", "destructive_level": "Probe", "attack_surface": "车机APP/应用", "required_params": "expected_usb_serial", "profiles": ["application"]},
    "poc39_syslog_export": {"protocol": "local", "severity": "Medium", "destructive_level": "Safe", "attack_surface": "系统配置/本地制品", "required_params": "expected_usb_serial", "profiles": ["local_artifact"]},
    "poc40_zygote": {"protocol": "local", "severity": "Critical", "destructive_level": "Disruptive", "is_disruptive": True, "attack_surface": "系统配置/本地制品", "required_params": "expected_usb_serial", "profiles": ["local_artifact"]},
    "poc41_selinux": {"protocol": "local", "severity": "Medium", "destructive_level": "Disruptive", "is_disruptive": True, "attack_surface": "系统配置/本地制品", "required_params": "expected_usb_serial", "profiles": ["local_artifact"]},
    "poc42_systdir_disabled": {"protocol": "local", "severity": "Medium", "destructive_level": "Disruptive", "is_disruptive": True, "attack_surface": "系统配置/本地制品", "required_params": "expected_usb_serial", "profiles": ["local_artifact"]},
    "poc44_procfs_hidepid": {"protocol": "local", "severity": "Medium", "destructive_level": "Probe", "attack_surface": "系统配置/本地制品", "required_params": "expected_usb_serial", "profiles": ["local_artifact"]},
    "poc45_libjepg_exported": {"protocol": "native", "severity": "High", "destructive_level": "Probe", "attack_surface": "第三方组件/高级漏洞", "required_params": "expected_usb_serial", "profiles": ["local_artifact"]},
    "poc120_webview_remote_url": {"protocol": "android", "severity": "Medium", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "android_source_fixture", "profiles": ["application"]},
    "poc121_webview_js_enabled": {"protocol": "android", "severity": "Medium", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "android_source_fixture", "profiles": ["application"]},
    "poc122_webview_mixed_content": {"protocol": "android", "severity": "Medium", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "android_source_fixture", "profiles": ["application"]},
    "poc123_sqlite_plaintext": {"protocol": "android", "severity": "High", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "sqlite_fixture_dir", "profiles": ["application"]},
    "poc124_sqlite_injection_pattern": {"protocol": "android", "severity": "High", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "android_source_fixture", "profiles": ["application"]},
    "poc125_sensitive_file_storage": {"protocol": "android", "severity": "High", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "app_data_fixture_dir", "profiles": ["application"]},
    "poc126_activity_export_intent_filter": {"protocol": "android", "severity": "High", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "android_manifest", "profiles": ["application"]},
    "poc127_service_export_permission": {"protocol": "android", "severity": "High", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "android_manifest", "profiles": ["application"]},
    "poc128_receiver_export_permission": {"protocol": "android", "severity": "High", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "android_manifest", "profiles": ["application"]},
    "poc129_provider_grant_uri": {"protocol": "android", "severity": "High", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "android_manifest", "profiles": ["application"]},
    "poc130_debug_log_sensitive": {"protocol": "android", "severity": "Medium", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "log_fixture", "profiles": ["application"]},
    "poc131_hardcoded_debug_endpoint": {"protocol": "android", "severity": "Medium", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "android_source_fixture", "profiles": ["application"]},
    "poc132_weak_crypto_ecb": {"protocol": "crypto", "severity": "Medium", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "android_source_fixture", "profiles": ["application"]},
    "poc133_weak_random_seed": {"protocol": "crypto", "severity": "Medium", "destructive_level": "Safe", "attack_surface": "车机APP/应用", "required_params": "android_source_fixture", "profiles": ["application"]},
    "poc134_doip_entity_status_probe": {"protocol": "doip", "severity": "Medium", "destructive_level": "Probe", "attack_surface": "网络服务", "required_params": "target_ip", "profiles": ["network"]},
    "poc135_doip_routing_activation_probe": {"protocol": "doip", "severity": "Medium", "destructive_level": "Probe", "attack_surface": "网络服务", "required_params": "target_ip", "profiles": ["network"]},
    "poc136_can_log_replay_safety_lint": {"protocol": "can", "severity": "Medium", "destructive_level": "Safe", "attack_surface": "CAN/UDS/OBD", "required_params": "can_log_fixture", "profiles": ["can_extended"]},
    "poc137_uds_negative_response_lint": {"protocol": "uds", "severity": "Medium", "destructive_level": "Safe", "attack_surface": "CAN/UDS/OBD", "required_params": "uds_log_fixture", "profiles": ["can_extended"]},
}

CATEGORY_LABELS = {
    "reconnaissance": "侦察",
    "network": "网络",
    "canbus": "CAN总线",
    "wireless": "无线",
    "application": "应用",
    "advanced": "高级",
    "new_network": "原厂PoC/网络",
    "new_application": "原厂PoC/应用",
    "new_advanced": "原厂PoC/组件",
    "new_system": "原厂PoC/系统",
    "new_wireless": "原厂PoC/无线",
    "new_can": "原厂PoC/CAN",
    "new_peripheral": "原厂PoC/外设",
    "new_general": "原厂PoC/通用",
    "new": "原厂PoC",
}


def extract_new_poc_tag(source_text: str, fallback: str) -> str:
    match = NEW_POC_TAG_PATTERN.search(source_text or "")
    if match:
        return " ".join(match.group(1).split()).strip()
    return fallback


def _text_blob(meta: dict[str, Any]) -> str:
    return " ".join(
        str(meta.get(k, ""))
        for k in ("poc_file", "poc_name", "category", "cve_id", "protocol")
    ).lower()


def infer_protocol(meta: dict[str, Any]) -> str:
    raw = str(meta.get("protocol") or "").strip().lower()
    if raw and raw not in {"unknown", "n/a", "none", "multi"}:
        return raw

    poc_file = str(meta.get("poc_file") or "")
    stem = Path(poc_file).stem
    if stem in NEW_POC_KNOWN:
        return str(NEW_POC_KNOWN[stem]["protocol"])

    text = _text_blob(meta)
    rules: list[tuple[tuple[str, ...], str]] = [
        (("icmp", "host_discovery"), "icmp"),
        (("mdns", "ssdp", "upnp", "snmp", "dhcp"), "udp"),
        (("tcp_port", "port_scan", "tbox"), "tcp"),
        (("http_service", "http_enum"), "http"),
        (("someip",), "someip"),
        (("doip",), "doip"),
        (("ssh",), "ssh"),
        (("telnet",), "telnet"),
        (("adb",), "adb"),
        (("mqtt",), "mqtt"),
        (("rtsp",), "rtsp"),
        (("dlna", "avtransport"), "http"),
        (("dbus",), "dbus"),
        (("ftp",), "ftp"),
        (("https", "tls", "openssl"), "tls"),
        (("webview", "apk_manifest", "debuggable", "allowbackup", "cleartext", "activity_export", "service_export", "provider", "broadcast", "schemeurl", "sharedprefs", "openfile", "strandhogg"), "android"),
        (("libav", "libpng", "libupnp", "libjpeg", "native"), "native"),
        (("bluetooth", "bt_sdp", "blueborne", "ble_", "_ble", "rfcomm"), "bluetooth"),
        (("wifi", "krack", "wpa"), "wifi"),
        (("can_bus", "uds", "obd", "isotp"), "can"),
        (("gps", "tpms", "v2x", "keyfob", "rf_", "sdr"), "rf"),
        (("airplay", "carplay", "mirror", "hiqnet"), "tcp"),
        (("usb",), "usb"),
    ]
    for tokens, protocol in rules:
        if any(token in text for token in tokens):
            return protocol

    category = str(meta.get("category") or "").lower()
    if category.startswith("new_"):
        if "network" in category:
            return "tcp"
        if "application" in category:
            return "android"
        if "wireless" in category:
            return "bluetooth"
        if "can" in category:
            return "can"
        if "peripheral" in category:
            return "usb"
        return "local"
    if category == "reconnaissance":
        if "icmp" in text:
            return "icmp"
        if "bt" in text or "bluetooth" in text:
            return "bluetooth"
        return "multi"
    if category == "network":
        return "tcp"
    if category == "canbus":
        return "can"
    if category == "wireless":
        return "rf"
    if category == "application":
        return "tcp"
    if category == "advanced":
        return "rf"
    return "multi"


def infer_attack_surface(meta: dict[str, Any]) -> str:
    existing = str(meta.get("attack_surface") or "").strip()
    if existing and existing != "其他":
        return existing

    stem = Path(str(meta.get("poc_file") or "")).stem
    if stem in NEW_POC_KNOWN:
        return str(NEW_POC_KNOWN[stem]["attack_surface"])

    text = _text_blob(meta)
    if any(x in text for x in ("can", "uds", "obd", "traffic_hijack")):
        return "CAN/UDS/OBD"
    if any(x in text for x in ("bluetooth", "ble", "wifi", "rf", "gps", "tpms", "v2x")):
        return "无线/外设接口"
    if any(x in text for x in ("adb", "ssh", "telnet", "mqtt", "rtsp", "http", "someip", "doip", "dlna", "ftp", "upnp")):
        return "网络服务"
    if any(x in text for x in ("webview", "apk", "debuggable", "allowbackup", "activity", "service", "provider", "broadcast", "scheme", "sharedprefs", "openfile", "carplay", "airplay", "mirror")):
        return "车机APP/应用"
    if any(x in text for x in ("firmware", "ota", "usb", "qnx")):
        return "固件/USB/OTA"
    if any(x in text for x in ("libav", "libpng", "openssl", "libjpeg", "libupnp")):
        return "第三方组件/高级漏洞"
    if any(x in text for x in ("selinux", "zygote", "procfs", "stack", "syslog", "fileacl")):
        return "系统配置/本地制品"
    return "其他"


def infer_new_poc_category_and_profiles(
    path: Path, source_text: str, poc_name: str,
) -> tuple[str, list[str], str]:
    stem = path.stem
    if stem in NEW_POC_KNOWN:
        known = NEW_POC_KNOWN[stem]
        profiles = list(known.get("profiles") or [])
        surface = str(known.get("attack_surface") or "其他")
        if "network" in profiles:
            return "new_network", profiles, surface
        if "application" in profiles:
            return "new_application", profiles, surface
        if "can_extended" in profiles or "can_gateway" in profiles:
            return "new_can", profiles, surface
        if "bluetooth" in profiles:
            return "new_wireless", profiles, surface
        if "usb_adb" in profiles:
            return "new_peripheral", profiles, surface
        if "advanced_network" in profiles:
            return "new_advanced", profiles, surface
        if "local_artifact" in profiles:
            return "new_system", profiles, surface
        return "new_general", profiles, surface

    src = (source_text or "").lower()
    text = f"{path.name} {poc_name}".lower()

    if "apk_manifest" in src or "usescleartexttraffic" in src or "debuggable" in src or "allowbackup" in src:
        return "new_application", ["application"], "车机APP/应用"
    if any(token in text for token in ("activity", "service", "provider", "broadcast", "receiver", "scheme", "webview", "sharedprefs", "openfile", "strandhogg", "sdcard", "db_export", "sqlite", "sensitive_file", "debug_log", "hardcoded_debug")):
        return "new_application", ["application"], "车机APP/应用"
    if any(token in text for token in ("adb", "telnet", "ssh", "ftp", "webindex", "hotspot")):
        return "new_network", ["network"], "网络服务"
    if any(token in text for token in ("doip", "someip", "xcp")):
        return "new_network", ["network"], "网络服务"
    if any(token in text for token in ("can", "uds", "isotp", "iso_tp", "j1939")):
        return "new_can", ["can_extended"], "CAN/UDS/OBD"
    if any(token in text for token in ("libupnp", "libav", "libpng", "openssl", "libjpeg", "weakaes", "pseudo_rand", "weak_crypto", "weak_random")):
        return "new_advanced", ["advanced_network"], "第三方组件/高级漏洞"
    if any(token in text for token in ("selinux", "stack", "zygote", "procfs", "syslog", "vaspace", "hidepid", "fileacl", "systdir")):
        return "new_system", ["local_artifact"], "系统配置/本地制品"
    if any(token in text for token in ("bluetooth", "bt")):
        return "new_wireless", ["bluetooth"], "无线/外设接口"
    if any(token in text for token in ("traffic_hijack", "bydtraffic")):
        return "new_can", ["can_extended"], "CAN/UDS/OBD"
    if any(token in text for token in ("usb", "installask")):
        return "new_peripheral", ["usb_adb"], "固件/USB/OTA"
    return "new_general", ["local_artifact"], "其他"


def enrich_new_poc_meta(path: Path, source_text: str, meta: dict[str, Any]) -> dict[str, Any]:
    title = extract_new_poc_tag(source_text, meta.get("poc_name", path.stem))
    category, profiles, attack_surface = infer_new_poc_category_and_profiles(path, source_text, title)
    standard_category = path.parts[0] if len(path.parts) > 1 else ""
    if standard_category in {"application", "advanced", "wireless", "canbus", "network", "reconnaissance"}:
        category = standard_category
    number_match = NEW_POC_FILE_PATTERN.match(path.name)
    display_id = meta.get("display_id") or (
        f"NEW-{number_match.group(1).zfill(2)}" if number_match else f"NEW-{path.stem}"
    )

    stem = path.stem
    known = NEW_POC_KNOWN.get(stem, {})

    meta["display_id"] = display_id
    meta["poc_name"] = title
    meta["category"] = category
    meta["attack_surface"] = attack_surface
    meta["profiles"] = profiles if isinstance(profiles, list) else [profiles]
    meta["severity"] = meta.get("severity") or known.get("severity") or "Medium"
    existing_destructive = str(meta.get("destructive_level") or "").strip()
    known_destructive = str(known.get("destructive_level") or "").strip()
    if known_destructive and (not existing_destructive or existing_destructive.lower() == "safe"):
        meta["destructive_level"] = known_destructive
    else:
        meta["destructive_level"] = existing_destructive or "Safe"
    meta["is_disruptive"] = bool(meta.get("is_disruptive") or known.get("is_disruptive") or False)
    meta["protocol"] = known.get("protocol") or meta.get("protocol") or ""
    meta["required_params"] = meta.get("required_params") or known.get("required_params") or ""
    if not meta["required_params"]:
        if "network" in category:
            meta["required_params"] = "target_ip"
        elif "wireless" in category:
            meta["required_params"] = "bluetooth_mac"
        elif "can" in category:
            meta["required_params"] = "can_interface"
        else:
            meta["required_params"] = "expected_usb_serial"
    return meta


def category_display_label(category: str) -> str:
    return CATEGORY_LABELS.get(str(category or "").strip(), str(category or ""))


def normalize_meta(meta: dict[str, Any]) -> dict[str, Any]:
    """统一补全协议/攻击面/分类显示，替换 unknown。"""
    meta["protocol"] = infer_protocol(meta)
    meta["attack_surface"] = infer_attack_surface(meta)
    meta["category_label"] = category_display_label(meta.get("category", ""))
    level = str(meta.get("destructive_level", "Safe")).lower()
    meta["high_risk"] = bool(meta.get("is_disruptive")) or level in {"disruptive", "restart", "dataloss", "brick"}
    return meta

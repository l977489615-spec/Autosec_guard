import os
import re

from poc_registry import get_poc_code, list_builtin_pocs
from security_utils import safe_resolve_within


SUPPORT_MODULES = {
    "iv_plugin_base.py",
    "poc_runtime_adapter.py",
    "advisory_audit_core.py",
    "active_validation_core.py",
    "probe_utils.py",
    "local_exp_stimulus.py",
    "wireless/wireless_cve_audit.py",
    "wireless_cve_audit.py",
    "canbus/can_bus_utils.py",
    "can_bus_utils.py",
}
NON_POC_SCRIPTS = {"run_experiment.py", "diagnostic_upnp.py", "deep_diagnostic.py"}

# 旧版短文件名 / 历史 poc_coverage 条目 → 当前运行时目录中的真实路径
LEGACY_POC_ALIASES: dict[str, str] = {
    "dynamic_unknown_service_probe": "network/15_CWE_200_Service_Probe_Active_Validation.py",
    "dynamic_0day": "network/15_CWE_200_Service_Probe_Active_Validation.py",
    "99_Dynamic_Unknown_Service_Probe.py": "network/15_CWE_200_Service_Probe_Active_Validation.py",
    "dynamic_unknown_protocol_fuzz": "network/16_Unknown_Protocol_Stateful_Fuzz_Validation.py",
    "network/09A_USB_ADB_Debug.py": "network/01_CWE_489_USB_ADB_Debug_Interface_Active_Validation.py",
    "network/09B_ADB_Debug_Port.py": "network/02_CVE_2018_6242_ADB_Debug_Port_Active_Validation.py",
    "network/10_SSH_Service.py": "network/03_CWE_200_SSH_Service_Active_Validation.py",
    "network/11_SSH_Weak_Creds.py": "network/04_CWE_521_SSH_Weak_Credentials_Active_Validation.py",
    "network/12_SSH_Hardcoded_Creds.py": "network/05_CWE_798_SSH_Hardcoded_Credentials_Active_Validation.py",
    "network/13_Telnet_Service.py": "network/06_CWE_319_Telnet_Service_Active_Validation.py",
    "network/14_Telnet_Weak_Creds.py": "network/07_CWE_521_Telnet_Weak_Credentials_Active_Validation.py",
    "network/15_FTP_Anonymous.py": "network/08_CWE_306_FTP_Anonymous_Active_Validation.py",
    "network/16_MQTT_Unauth.py": "network/09_CWE_306_MQTT_Unauth_Active_Validation.py",
    "network/17_DBus_Anon_Auth.py": "network/10_CVE_2015_5611_Auth_Active_Validation.py",
    "network/18_RTSP_Log_Leak.py": "network/11_CWE_200_RTSP_Log_Leak_Active_Validation.py",
    "network/19_DLNA_AVTransport_Unauth.py": "network/12_CWE_306_DLNA_AVTransport_Unauth_Active_Validation.py",
    "network/20_HTTPS_No_Cert_Pin.py": "network/13_CWE_295_HTTPS_No_Cert_Pin_Active_Validation.py",
    "network/21_SOMEIP_Service_Discovery.py": "network/14_CWE_200_SOMEIP_Service_Discovery_Active_Validation.py",
    "10_SSH_Weak_Creds.py": "network/04_CWE_521_SSH_Weak_Credentials_Active_Validation.py",
    "11_SSH_Weak_Creds.py": "network/04_CWE_521_SSH_Weak_Credentials_Active_Validation.py",
    "12_SSH_Hardcoded_Creds.py": "network/05_CWE_798_SSH_Hardcoded_Credentials_Active_Validation.py",
    "20_HTTPS_No_Cert_Pin.py": "network/13_CWE_295_HTTPS_No_Cert_Pin_Active_Validation.py",
}


def is_executable_poc_name(name: str) -> bool:
    normalized = str(name or "").replace("\\", "/").lstrip("./")
    basename = os.path.basename(normalized)
    parts = [part for part in normalized.split("/") if part]
    if any(part.startswith("_") for part in parts[:-1]):
        return False
    return (
        normalized.endswith(".py")
        and not basename.startswith("__")
        and basename not in SUPPORT_MODULES
        and basename not in NON_POC_SCRIPTS
        and normalized not in SUPPORT_MODULES
    )


def _normalize_poc_reference(poc_filename: str) -> str:
    return str(poc_filename or "").replace("\\", "/").strip().lstrip("./")


def _tokenize_poc_reference(poc_filename: str) -> set[str]:
    return set(re.findall(r"[A-Za-z0-9]+", _normalize_poc_reference(poc_filename).lower()))


def _fuzzy_match_poc_name(pocs_dir: str, poc_filename: str) -> str | None:
    """Best-effort match for LLM-invented short names; only used after alias lookup fails."""
    ref = _normalize_poc_reference(poc_filename)
    if not ref:
        return None
    ref_tokens = _tokenize_poc_reference(ref)
    if len(ref_tokens) < 2:
        return None
    ref_category = ref.split("/", 1)[0] if "/" in ref else ""
    candidates: list[tuple[int, str]] = []
    for name in list_available_poc_names(pocs_dir):
        name_tokens = _tokenize_poc_reference(name)
        score = len(ref_tokens & name_tokens)
        if ref_category and name.startswith(f"{ref_category}/"):
            score += 1
        if score >= 3:
            candidates.append((score, name))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (-item[0], item[1]))
    best_score, best_name = candidates[0]
    second_score = candidates[1][0] if len(candidates) > 1 else 0
    if best_score <= second_score:
        return None
    return best_name


def resolve_poc_reference(pocs_dir: str, poc_filename: str) -> tuple[str | None, str]:
    """Resolve a PoC reference to a catalog path; returns (normalized_path, match_kind)."""
    ref = _normalize_poc_reference(poc_filename)
    if not ref:
        return None, "empty"

    poc_path, normalized = resolve_poc_path(pocs_dir, ref)
    if poc_path and normalized:
        return normalized, "exact"

    alias = LEGACY_POC_ALIASES.get(ref) or LEGACY_POC_ALIASES.get(os.path.basename(ref))
    if alias:
        poc_path, normalized = resolve_poc_path(pocs_dir, alias)
        if poc_path and normalized:
            return normalized, "alias"

    fuzzy = _fuzzy_match_poc_name(pocs_dir, ref)
    if fuzzy:
        return fuzzy, "fuzzy"

    return None, "unresolved"


def resolve_poc_path(pocs_dir: str, poc_filename: str) -> tuple[str | None, str | None]:
    if not poc_filename:
        return None, None

    ref = _normalize_poc_reference(poc_filename)
    alias = LEGACY_POC_ALIASES.get(ref) or LEGACY_POC_ALIASES.get(os.path.basename(ref))
    if alias:
        poc_filename = alias
    else:
        poc_filename = ref

    # 安全校验：只允许 .py 且必须解析到 pocs_dir 之内（防路径穿越）。
    # 拒绝 ../、绝对路径、以及非 PoC 命名（如 __init__.py、支持模块）。
    if not is_executable_poc_name(poc_filename):
        # 仍可能是内建 PoC（不落盘），交由 builtin 分支判断
        builtin_code, normalized = get_poc_code(poc_filename)
        if builtin_code and normalized and is_executable_poc_name(normalized):
            safe_builtin = safe_resolve_within(pocs_dir, normalized)
            if safe_builtin:
                return safe_builtin, normalized
        return None, None

    # 直接路径命中（经容器边界校验）
    safe_path = safe_resolve_within(pocs_dir, poc_filename)
    if safe_path and os.path.exists(safe_path):
        return safe_path, os.path.relpath(safe_path, os.path.realpath(pocs_dir))

    # 按 basename 在 pocs_dir 树内查找（basename 已去除任何目录成分，天然防穿越）
    basename = os.path.basename(poc_filename)
    real_base = os.path.realpath(pocs_dir)
    for dirpath, _, filenames in os.walk(real_base):
        if basename in filenames:
            found = os.path.join(dirpath, basename)
            return found, os.path.relpath(found, real_base)

    # 内建（embedded）PoC：不落盘，返回逻辑路径
    builtin_code, normalized = get_poc_code(poc_filename)
    if builtin_code and normalized and is_executable_poc_name(normalized):
        safe_builtin = safe_resolve_within(pocs_dir, normalized)
        if safe_builtin:
            return safe_builtin, normalized

    return None, None


def resolve_poc_source(pocs_dir: str, poc_filename: str) -> tuple[str | None, str | None, str | None]:
    poc_path, normalized = resolve_poc_path(pocs_dir, poc_filename)
    if not poc_path or not normalized:
        return None, None, None

    if os.path.exists(poc_path):
        with open(poc_path, "r", encoding="utf-8") as handle:
            return poc_path, normalized, handle.read()

    builtin_code, builtin_name = get_poc_code(normalized)
    if builtin_code and builtin_name:
        return poc_path, builtin_name, builtin_code
    return poc_path, normalized, None


def list_available_poc_names(pocs_dir: str) -> list[str]:
    names: set[str] = set()
    if os.path.isdir(pocs_dir):
        for dirpath, dirnames, filenames in os.walk(pocs_dir):
            dirnames[:] = [
                d for d in dirnames
                if not d.startswith('.') and not d.startswith('_') and d != '.venv' and d != '__pycache__'
            ]
            for filename in filenames:
                if is_executable_poc_name(filename):
                    names.add(os.path.relpath(os.path.join(dirpath, filename), pocs_dir))
    names.update(name for name in list_builtin_pocs() if is_executable_poc_name(name))
    return sorted(names)

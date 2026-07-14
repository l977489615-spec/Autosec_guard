#!/usr/bin/env python3
"""Audit PoC files for exploit-level readiness.

EXP-ready means the plugin has all of the following:
1. an attack stimulus/payload or crafted sample;
2. code that sends, executes, replays, or opens that stimulus against a target;
3. observable result handling such as crash, reset, unauthorized access,
   data disclosure, state change, or target-side manual confirmation;
4. a safety gate for disruptive actions.

Reconnaissance scripts are reported separately because they are not vulnerability
exploits and should not be counted as EXP PoCs.
"""
from __future__ import annotations

import argparse
import ast
import csv
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


SERVER_DIR = Path(__file__).resolve().parent
POCS_DIR = SERVER_DIR / "pocs"
REPORTS_DIR = SERVER_DIR / "reports"

SUPPORT_FILES = {
    "iv_plugin_base.py",
    "active_validation_core.py",
    "advisory_audit_core.py",
    "poc_runtime_adapter.py",
    "can_bus_utils.py",
}

PROFESSIONAL_TIER_ORDER = {
    "RECON": 0,
    "PASSIVE": 1,
    "AUTHENTICATED_CONFIG": 2,
    "ACTIVE_PROBE": 3,
    "ACTIVE_VALIDATION": 4,
}

ATTACK_INPUT_RE = re.compile(
    r"active_payload_(?:text|hex)|sample_path|_write_.*sample|payload\s*=|"
    r"payload_bytes|crafted|malformed|overflow|traversal|injection|replay|"
    r"evil twin|beacon|deauth|credential|wordlist|subscribe|publish|"
    r"uds|diagnostic session|security access|readmemory|routinecontrol|"
    r"sqli|xss|intent|content://|service call|am start|exec_command\(|"
    r"pattern\s*=\s*re\.compile|check_manifest\(|run_apk_manifest_check\(|"
    r"addjavascriptinterface|setallowfileaccess|getexternalstoragedirectory|"
    r"debuggable|allowbackup|usescleartexttraffic|taskaffinity|exported|"
    r"mitm|self-signed|certificate|spoof|spoofing|downgrade|pairing|passkey|"
    r"ctkd|knob|blurtooth|bluffs|krack|handshake|key reinstall|"
    r"flood_msg|sensor_id|gpssim|baseband|xhr\.open\(|receive_loot|"
    r"route activation|routing activation|findservice|offerservice|"
    r"default credentials|hardcoded|debug endpoint|toctou|evil_file|legit_file|"
    r"auth bypass|admin panel|control port|devmode|developer mode|"
    r"hidden_api_blacklist_exemptions|local_version\(|android_exposure\(|"
    r"null cid|l2cap connection request|malicious_filename|malicious_update\.zip|"
    r"ifs-root\.ifs|swdl\.iso|usb node|echo -ne|lights on",
    re.IGNORECASE,
)
EXECUTION_RE = re.compile(
    r"sendall\(|\.send\(|requests\.(?:post|put|delete|get)\(|"
    r"bus\.send\(|sendp\(|client\.connect\(|exec_command\(|recv\(|"
    r"connect_ex\(|\.connect\(|sendto\(|bind\(|"
    r"subprocess\.run\(|os\.system\(|socket\.create_connection\(|"
    r"adb|nmap|scapy|bluetooth|hcitool|l2ping|paramiko|"
    r"run_active_validation\(|execute_check_callable\(|run_apk_manifest_check\(|ensure_manifest\(|"
    r"local_version\(|android_exposure\(|"
    r"adb_pull\(|et\.parse\(|os\.walk\(|glob\.glob\(",
    re.IGNORECASE,
)
EXP_EXECUTION_RE = re.compile(
    r"sendall\(|\.send\(|requests\.(?:post|put|delete)\(|bus\.send\(|"
    r"active_payload_(?:text|hex)|sample_path|_write_.*sample|"
    r"sendp\(|client\.connect\(|exec_command\(|execute_check_callable\(|"
    r"connect_ex\(|\.connect\(|sendto\(|bind\(|subprocess\.(?:run|popen)\(|"
    r"shutil\.copy\(|zipfile\.zipfile\(|os\.system\(|"
    r"malicious_filename|malicious_update\.zip|ifs-root\.ifs|swdl\.iso|"
    r"payload_dir\s*=|hackrf_transfer|rpitx|echo -ne|"
    r"run_active_validation\(|run_apk_manifest_check\(|local_version\(|android_exposure\(|"
    r"adb_pull\(|ensure_manifest\(|"
    r"adb.+(?:am start|am broadcast|content query|content call|service call|input text)|"
    r"subprocess\.run\([^)]*(?:am|content|service|hcitool|l2ping|ffmpeg|chromium|decoder|adb)",
    re.IGNORECASE | re.DOTALL,
)
OBSERVATION_RE = re.compile(
    r"vulnerable|phenomenon|crash|asan|heap|segmentation fault|reset|"
    r"unauthorized|sensitive|leak|disclosure|state change|manual|"
    r"requires_manual_review|operator_action|response_excerpt|after|before|"
    r"login successful|anonymous auth|wildcard subscribe|login incorrect|"
    r"session .* opened|auto.?connect|beacon .* sent|rejected unsigned package|"
    r"\bok\b|\bfound\b|risk_level|manifest=|exported .* detected|"
    r"scheme urls declared|api-class map|not vulnerable|inconclusive|"
    r"port reachable|banner|accepted|rejected|response:|"
    r"strictly verified|unverified|target is secure|transmission verified|"
    r"observer drift|moved .* toward spoofed coordinates|did not visit|"
    r"pairing .* not yet demonstrated|acceptance unverified|"
    r"follow-up state query confirmed|follow-up state query did not confirm|"
    r"self-signed cert|certificate verification|copied artifact|hash matches evil payload|"
    r"aslr|randomize_va_space|完全随机化|基本随机化|已禁用|"
    r"高危漏洞存在|中危漏洞存在|未发现直接篡改风险|"
    r"debug endpoint count|plaintext sqlite hits|"
    r"sent zero-length doip routing pre-check|开发者模式可能已激活|调试端口|"
    r"已生成.*样本|恶意.*已在本地生成|目标未访问|未观察到.*证据|"
    r"注入成功|注入未生效|恢复成功|affected_before|patch_declared|"
    r"no cache trace collection|no pairing, bond replacement, or key overwrite was attempted|"
    r"需在目标.*确认|需人工确认|请观察|操作被执行|非授权操作|"
    r"target acceptance unverified|web管理面板|ota/控制端口",
    re.IGNORECASE,
)
SAFETY_GATE_RE = re.compile(
    r"allow_disruptive|is_disruptive\s*=\s*True|meta_destructive_level\s*=\s*['\"]"
    r"(Restart|DataLoss|Brick|Disruptive|Probe)['\"]|requires_manual_review|manual_confirmation",
    re.IGNORECASE,
)
ACTIVE_HARNESS_RE = re.compile(
    r"active_payload_(?:text|hex)|build_local_sample_probe|run_local_target",
    re.IGNORECASE,
)
STATIC_AUDIT_RE = re.compile(
    r"Version_Audit|Cleartext_HTTP_Audit|Debuggable_App_Audit|AllowBackup_Audit|"
    r"Exported_.*_Audit|Plaintext_Audit|Sensitive_.*_Audit|Hardcoded_.*_Audit|"
    r"Weak_(?:Crypto|Random)|Syslog_Exposure_Audit|Database_Export_Audit|"
    r"Permission_Audit|Provider_URI_Grant_Audit|Intent_Filter_Audit|"
    r"Scheme_URL_Export_Audit|Log_Exposure_Audit|File_Storage_Audit|"
    r"Certificate_Validation_Audit|Signature_Verification_Audit",
    re.IGNORECASE,
)


@dataclass
class ExpFinding:
    file: str
    category: str
    poc_name: str
    cve_id: str
    protocol: str
    grade: str
    attack_input: bool
    execution_path: bool
    observable_result: bool
    safety_gate: bool
    is_recon: bool
    missing: list[str]
    validation_tier: str
    detection_confidence: int
    execution_safety: str
    evidence_basis: list[str]
    exp_capability: str
    professional_grade: str
    not_native_exp: bool
    market_baseline: str
    market_gap: str
    scanner_ready: bool
    scanner_grade: str
    active_ready: bool
    active_grade: str
    product_ready: bool
    product_grade: str


def _literal_assigns(source: str) -> dict[str, Any]:
    values: dict[str, Any] = {}
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return values
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for item in node.body:
            if not isinstance(item, ast.Assign):
                continue
            try:
                value = ast.literal_eval(item.value)
            except Exception:
                continue
            for target in item.targets:
                if isinstance(target, ast.Name):
                    values[target.id] = value
        if values:
            break
    return values


def _grade(item: ExpFinding) -> str:
    if item.is_recon:
        return "RECON_NOT_EXP"
    if item.attack_input and item.execution_path and item.observable_result and item.safety_gate:
        return "EXP_READY"
    if item.scanner_ready:
        return "SCANNER_READY"
    if item.attack_input and item.execution_path and item.observable_result:
        return "EXP_NEEDS_SAFETY_GATE"
    if item.attack_input and item.execution_path:
        return "PAYLOAD_NO_OBSERVATION"
    if item.attack_input:
        return "PAYLOAD_NOT_EXECUTED"
    if item.execution_path:
        return "PROBE_ONLY"
    return "STATIC_OR_METADATA"


def _is_static_audit(path: Path, source: str) -> bool:
    if not STATIC_AUDIT_RE.search(path.name):
        return False
    return not bool(EXP_EXECUTION_RE.search(source) or ACTIVE_HARNESS_RE.search(source))


def _professional_classification(
    path: Path,
    source: str,
    meta: dict[str, Any],
    *,
    is_recon: bool,
    framework_payload: bool,
    framework_harness: bool,
    static_audit: bool,
) -> dict[str, Any]:
    name = path.name
    category = path.relative_to(POCS_DIR).parts[0] if path.is_relative_to(POCS_DIR) else ""
    protocol = str(meta.get("meta_protocol") or "").lower()
    destructive_level = str(meta.get("meta_destructive_level") or "").lower()
    is_disruptive = bool(meta.get("is_disruptive"))
    profiles = [str(item).lower() for item in meta.get("meta_profiles", [])]

    evidence: list[str] = []
    if re.search(r"banner|version|inventory|service_banner|software_inventory|sbom", source, re.I):
        evidence.append("inventory")
    if re.search(r"adb|manifest|config|policy|fixture|permission|registry|package", source, re.I):
        evidence.append("authenticated_config")
    if re.search(r"socket\.create_connection|requests\.get|PING|OPTIONS \* RTSP|tcp_liveness|active_probe", source, re.I):
        evidence.append("protocol_probe")
    if re.search(r"sendall\(|bus\.send\(|requests\.(?:post|put|delete)\(", source, re.I):
        evidence.append("crafted_payload")
    if re.search(r"crash|asan|segmentation fault|reset|shell|before|after|returncode", source, re.I):
        evidence.append("crash_observed")
    if re.search(r"requires_manual_review|operator_action|manual_confirmation|operator_observation", source, re.I):
        evidence.append("manual_confirmation")
    if not evidence:
        evidence.append("metadata")

    native_execution = bool(re.search(
        r"sendall\(|bus\.send\(|requests\.(?:post|put|delete)\(|subprocess\.run\(|"
        r"connect_ex\(|\.recv\(|ssl\.create_default_context\(|http\.server\.httpserver\(|"
        r"open_can_bus\(|can\.message\(",
        source,
        re.I,
    ))
    native_observation = bool(re.search(
        r"crash|reset|unauthorized|shell|vulnerable\s*:\s*True|before|after|returncode|"
        r"banner|evidence|accepted|rejected|login succeeded|anonymous login|"
        r"loot|captured_data|self-signed cert|明文协议|高风险|中风险|"
        r"存在安全风险|存在DoS风险",
        source,
        re.I,
    ))
    has_local_lab_probe = bool(re.search(r"build_local_sample_probe|run_local_target|sample_path|_write_.*sample", source, re.I))
    name_lower = name.lower()
    config_or_version_audit = bool(
        re.search(
            r"version_audit|cleartext_http_audit|debuggable_app_audit|allowbackup_audit|"
            r"exported_.*_audit|permission_audit|certificate_validation_audit|"
            r"signature_verification_audit|hardcoded|weak_(?:crypto|random)|"
            r"policy_audit|file_acl|aslr|stack_canary|hidepid",
            name_lower,
            re.I,
        )
    )
    run_active_wrapper = "run_active_validation(" in source

    if is_recon:
        tier = "RECON"
        confidence = 50
        safety = "safe"
        capability = "none"
    elif config_or_version_audit and not (framework_payload or framework_harness or has_local_lab_probe):
        tier = "AUTHENTICATED_CONFIG" if "authenticated_config" in evidence else "PASSIVE"
        confidence = 75 if tier == "AUTHENTICATED_CONFIG" else 60
        safety = "safe"
        capability = "none"
    elif framework_payload or has_local_lab_probe or framework_harness:
        tier = "ACTIVE_VALIDATION"
        confidence = 90 if has_local_lab_probe else 85
        safety = "approval_required" if is_disruptive or destructive_level in {"disruptive", "restart", "dataloss", "brick"} else "intrusive"
        capability = "supported_harness"
    elif native_execution and native_observation and not run_active_wrapper and not config_or_version_audit and ("crafted_payload" in evidence or "crash_observed" in evidence):
        tier = "ACTIVE_VALIDATION"
        confidence = 100 if is_disruptive or destructive_level in {"disruptive", "restart", "dataloss", "brick"} else 95
        safety = "approval_required" if is_disruptive or destructive_level in {"disruptive", "restart", "dataloss", "brick"} else "intrusive"
        capability = "native_verified"
    elif "run_active_validation(" in source or protocol in {"http", "https", "http2", "redis", "airplay", "rtsp", "tcp"}:
        tier = "ACTIVE_PROBE"
        confidence = 70
        safety = "low_impact"
        capability = "none"
    elif static_audit or "audit" in name.lower() or category in {"application", "advanced", "network", "wireless", "canbus"}:
        tier = "AUTHENTICATED_CONFIG" if "authenticated_config" in evidence or any(p in profiles for p in ("usb_adb", "local_artifact")) else "PASSIVE"
        confidence = 75 if tier == "AUTHENTICATED_CONFIG" else 60
        safety = "safe"
        capability = "none"
    else:
        tier = "PASSIVE"
        confidence = 50
        safety = "safe"
        capability = "none"

    not_native = capability != "native_verified"
    professional_grade = f"{tier}:{capability}"
    return {
        "validation_tier": tier,
        "detection_confidence": confidence,
        "execution_safety": safety,
        "evidence_basis": sorted(set(evidence)),
        "exp_capability": capability,
        "professional_grade": professional_grade,
        "not_native_exp": not_native,
    }


def _market_baseline_mapping(professional: dict[str, Any]) -> tuple[str, str]:
    tier = professional["validation_tier"]
    capability = professional["exp_capability"]
    if tier == "RECON":
        return ("Greenbone Discovery / Nmap host-discovery", "not-a-vuln-check")
    if tier == "PASSIVE":
        return ("Greenbone inventory-only / banner-only check", "no-active-trigger")
    if tier == "AUTHENTICATED_CONFIG":
        return ("Tenable/Greenbone local security checks", "authenticated-but-not-triggering")
    if tier == "ACTIVE_PROBE":
        return ("Nmap safe/intrusive NSE or Nuclei request-only check", "probe-without-proof-of-trigger")
    if tier == "ACTIVE_VALIDATION":
        return ("Nuclei targeted-request with explicit matcher", "good-remote-check")
    return ("Unclassified", "review-needed")


def _scanner_grade(
    *,
    is_recon: bool,
    attack_input: bool,
    execution_path: bool,
    observable_result: bool,
    safety_gate: bool,
    validation_tier: str,
    execution_safety: str,
    source: str,
) -> tuple[bool, str]:
    if is_recon:
        return False, "recon"

    source_lower = source.lower()
    active_wrapper = "run_active_validation(" in source_lower
    local_check = any(
        token in source_lower for token in (
            "execute_check_callable(",
            "run_apk_manifest_check(",
            "adb_pull(",
            "ensure_manifest(",
            "check_manifest(",
            "local_version(",
            "android_exposure(",
            "xml.etree.elementtree",
            "et.parse(",
            "os.walk(",
        )
    )
    protocol_check = validation_tier in {"ACTIVE_PROBE", "ACTIVE_VALIDATION"}
    authenticated_local = validation_tier in {"AUTHENTICATED_CONFIG", "PASSIVE"} and local_check

    if active_wrapper and execution_path:
        if observable_result:
            return True, "request-based-with-matcher"
        return True, "request-based-active-probe"

    ready = execution_path and observable_result and (
        attack_input or protocol_check or authenticated_local
    )
    if not ready:
        return False, "missing-real-check-path"
    if safety_gate:
        return True, "intrusive-or-gated"
    if execution_safety in {"safe", "low_impact", "probe"} or authenticated_local:
        return True, "scanner-safe"
    return True, "scanner-real-check"


def _active_grade(
    *,
    is_recon: bool,
    attack_input: bool,
    execution_path: bool,
    observable_result: bool,
    safety_gate: bool,
    validation_tier: str,
    execution_safety: str,
    exp_capability: str,
    source: str,
) -> tuple[bool, str]:
    if is_recon:
        return False, "recon"

    tier = (validation_tier or "").upper()
    source_lower = source.lower()
    authenticated_local_check = (
        execution_path
        and any(
            token in source_lower for token in (
                "execute_check_callable(",
                "run_apk_manifest_check(",
                "ensure_manifest(",
                "adb_pull(",
                "et.parse(",
                "xml.etree.elementtree",
                "os.walk(",
                "local_version(",
                "android_exposure(",
                "wpa_cli",
                "dumpsys",
                "getprop",
                "bluetoothctl",
                "krack-test-client.py",
                "ethtool",
                "_driver_info(",
            )
        )
    )
    native_socket_probe = (
        execution_path
        and observable_result
        and any(
            token in source_lower for token in (
                "connect_ex(",
                ".recv(",
                "socket.socket(",
                "ssl.create_default_context(",
                "socket.create_connection(",
            )
        )
    )
    fieldbus_or_local_stimulus = (
        execution_path
        and any(
            token in source_lower for token in (
                "bus.send(",
                "open_can_bus(",
                "can.message(",
                "http.server.httpserver(",
                "captured_data",
                "xmlhttprequest",
                "subprocess.popen(",
                "tool_path = shutil.which(",
                "hackrf_transfer",
                "rpitx",
                "gps-sdr-sim",
                "os.makedirs(",
                "shutil.copy(",
                "threading.thread(",
                "touch ",
            )
        )
    )
    framework_request_probe = (
        "run_active_validation(" in source_lower
        and execution_path
    )
    external_command_harness = (
        "build_local_sample_probe(" in source_lower
        and "run_local_target(" not in source_lower
        and not any(
            token in source_lower for token in (
                "shutil.which(",
                "subprocess.run(",
                "subprocess.popen(",
                "socket.create_connection(",
                "requests.post(",
                "requests.put(",
                "sendall(",
                "bus.send(",
                ".send(",
                "open_can_bus(",
            )
        )
    )
    native_remote = (
        tier == "ACTIVE_VALIDATION"
        and exp_capability == "native_verified"
        and execution_path
        and observable_result
    )
    active_harness = (
        tier == "ACTIVE_VALIDATION"
        and execution_path
        and observable_result
        and (
            "build_local_sample_probe" in source_lower
            or "run_local_target" in source_lower
            or "sample_path" in source_lower
            or "operator_payload_param" in source_lower
            or "active_payload_param" in source_lower
        )
    )
    protocol_probe = (
        tier == "ACTIVE_PROBE"
        and execution_path
        and observable_result
        and (
            "socket.create_connection(" in source_lower
            or "requests.get(" in source_lower
            or "tcp_liveness" in source_lower
            or "http_probe" in source_lower
            or "redis_probe" in source_lower
            or "airplay_rtsp_probe" in source_lower
            or "run_active_validation(" in source_lower
        )
    )
    direct_payload = attack_input and execution_path and observable_result and safety_gate

    if external_command_harness:
        return False, "external-command-harness"
    if native_remote:
        return True, "native-remote-active"
    if framework_request_probe:
        return True, "framework-request-probe"
    if authenticated_local_check:
        return True, "authenticated-local-check"
    if native_socket_probe:
        return True, "native-socket-probe"
    if fieldbus_or_local_stimulus:
        return True, "fieldbus-or-local-stimulus"
    if active_harness:
        return True, "active-trigger-capable"
    if protocol_probe:
        return True, "protocol-active-probe"
    if direct_payload:
        return True, "direct-payload-with-gate"
    if tier in {"AUTHENTICATED_CONFIG", "PASSIVE"}:
        return False, "config-or-passive-only"
    if tier == "ACTIVE_VALIDATION":
        return False, "active-metadata-without-trigger-path"
    if tier == "ACTIVE_PROBE":
        return False, "request-wrapper-without-real-observation"
    if execution_safety in {"safe", "low_impact"}:
        return False, "safe-check-without-active-trigger"
    return False, "review-needed"


def _product_grade(
    *,
    is_recon: bool,
    scanner_ready: bool,
    active_ready: bool,
    validation_tier: str,
    execution_safety: str,
    active_grade: str,
    source: str,
) -> tuple[bool, str]:
    if is_recon:
        return False, "recon"
    if not scanner_ready:
        return False, "below-scanner-baseline"
    if not active_ready:
        return False, "below-active-baseline"
    source_lower = source.lower()
    if (
        "build_local_sample_probe(" in source_lower
        and "run_local_target(" not in source_lower
        and not any(
            token in source_lower for token in (
                "shutil.which(",
                "subprocess.run(",
                "subprocess.popen(",
                "socket.create_connection(",
                "requests.post(",
                "requests.put(",
                "sendall(",
                "bus.send(",
                ".send(",
                "open_can_bus(",
            )
        )
    ):
        return False, "external-command-harness"
    tier = (validation_tier or "").upper()
    if tier in {"ACTIVE_PROBE", "ACTIVE_VALIDATION"}:
        return True, f"{tier.lower()}-product-check"
    if active_grade in {
        "authenticated-local-check",
        "native-socket-probe",
        "fieldbus-or-local-stimulus",
        "framework-request-probe",
    }:
        return True, "validated-defensive-check"
    if execution_safety in {"safe", "low_impact", "intrusive", "approval_required"}:
        return True, "controlled-product-check"
    return False, "review-needed"


def audit_file(path: Path) -> ExpFinding | None:
    rel = path.relative_to(SERVER_DIR).as_posix()
    if path.name in SUPPORT_FILES or ".venv" in path.parts or "_experiment" in path.parts:
        return None
    source = path.read_text(encoding="utf-8", errors="ignore")
    if "IVIVulnerabilityPlugin" not in source or "def exploit" not in source:
        return None
    meta = _literal_assigns(source)
    category = path.relative_to(POCS_DIR).parts[0] if path.is_relative_to(POCS_DIR) else ""
    is_recon = category == "reconnaissance" or "recon" in [str(x).lower() for x in meta.get("meta_profiles", [])]
    static_audit = _is_static_audit(path, source)
    framework_payload = "run_active_validation(" in source and bool(
        re.search(r"active_payload_(?:text|hex)|build_local_sample_probe|run_local_target|sample_path|_write_.*sample", source)
    )
    framework_harness = "run_active_validation(" in source and bool(ACTIVE_HARNESS_RE.search(source))
    attack_input = (bool(ATTACK_INPUT_RE.search(source)) or framework_payload or framework_harness) and not static_audit
    execution_path = (bool(EXP_EXECUTION_RE.search(source)) or framework_payload or framework_harness) and not static_audit
    observable_result = (bool(OBSERVATION_RE.search(source)) or framework_payload or framework_harness) and not static_audit
    professional = _professional_classification(
        path,
        source,
        meta,
        is_recon=is_recon,
        framework_payload=framework_payload,
        framework_harness=framework_harness,
        static_audit=static_audit,
    )
    finding = ExpFinding(
        file=rel,
        category=category,
        poc_name=str(meta.get("meta_poc_name") or path.stem),
        cve_id=str(meta.get("meta_cve_id") or ""),
        protocol=str(meta.get("meta_protocol") or ""),
        grade="",
        attack_input=attack_input,
        execution_path=execution_path,
        observable_result=observable_result,
        safety_gate=bool(SAFETY_GATE_RE.search(source)),
        is_recon=is_recon,
        missing=[],
        validation_tier=professional["validation_tier"],
        detection_confidence=professional["detection_confidence"],
        execution_safety=professional["execution_safety"],
        evidence_basis=professional["evidence_basis"],
        exp_capability=professional["exp_capability"],
        professional_grade=professional["professional_grade"],
        not_native_exp=professional["not_native_exp"],
        market_baseline=_market_baseline_mapping(professional)[0],
        market_gap=_market_baseline_mapping(professional)[1],
        scanner_ready=False,
        scanner_grade="",
        active_ready=False,
        active_grade="",
        product_ready=False,
        product_grade="",
    )
    finding.scanner_ready, finding.scanner_grade = _scanner_grade(
        is_recon=is_recon,
        attack_input=attack_input,
        execution_path=execution_path,
        observable_result=observable_result,
        safety_gate=finding.safety_gate,
        validation_tier=finding.validation_tier,
        execution_safety=finding.execution_safety,
        source=source,
    )
    finding.active_ready, finding.active_grade = _active_grade(
        is_recon=is_recon,
        attack_input=attack_input,
        execution_path=execution_path,
        observable_result=observable_result,
        safety_gate=finding.safety_gate,
        validation_tier=finding.validation_tier,
        execution_safety=finding.execution_safety,
        exp_capability=finding.exp_capability,
        source=source,
    )
    finding.product_ready, finding.product_grade = _product_grade(
        is_recon=is_recon,
        scanner_ready=finding.scanner_ready or finding.grade in {"EXP_READY", "SCANNER_READY"},
        active_ready=finding.active_ready,
        validation_tier=finding.validation_tier,
        execution_safety=finding.execution_safety,
        active_grade=finding.active_grade,
        source=source,
    )
    if not finding.attack_input:
        finding.missing.append("attack_input")
    if not finding.execution_path:
        finding.missing.append("execution_path")
    if not finding.observable_result:
        finding.missing.append("observable_result")
    if not finding.safety_gate and not finding.is_recon:
        finding.missing.append("safety_gate")
    finding.grade = _grade(finding)
    return finding


def audit_all() -> list[ExpFinding]:
    findings: list[ExpFinding] = []
    for path in sorted(POCS_DIR.rglob("*.py")):
        item = audit_file(path)
        if item:
            findings.append(item)
    return findings


def write_reports(findings: list[ExpFinding], prefix: str) -> tuple[Path, Path]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = REPORTS_DIR / f"{prefix}.json"
    csv_path = REPORTS_DIR / f"{prefix}.csv"
    json_path.write_text(
        json.dumps([asdict(item) for item in findings], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(findings[0]).keys()) if findings else ["file"])
        writer.writeheader()
        for item in findings:
            row = asdict(item)
            row["missing"] = ",".join(item.missing)
            writer.writerow(row)
    return json_path, csv_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit PoC exploit-level readiness")
    parser.add_argument("--fail-on-non-exp", action="store_true", help="exit non-zero if vulnerability PoCs are not EXP_READY")
    parser.add_argument("--prefix", default="exp_readiness", help="report filename prefix under server/reports")
    args = parser.parse_args()

    findings = audit_all()
    counts = Counter(item.grade for item in findings)
    by_category = Counter(item.category for item in findings)
    by_baseline = Counter(item.market_baseline for item in findings)
    scanner_ready_count = sum(1 for item in findings if item.scanner_ready or item.grade == "EXP_READY")
    active_ready_count = sum(1 for item in findings if not item.is_recon and item.active_ready)
    product_ready_count = sum(1 for item in findings if not item.is_recon and item.product_ready)
    json_path, csv_path = write_reports(findings, args.prefix)

    # ── Detection quality breakdown (product-grade audit) ─────────────────
    detection_quality = _detection_quality_breakdown(POCS_DIR)

    print("=" * 68)
    print(f"  AutoSec Guard – ProductGrade Audit Report")
    print("=" * 68)
    print(f"  Total plugins audited    : {len(findings)}")
    print(f"  EXP_READY (scanner tier) : {counts.get('EXP_READY', 0)}")
    print(f"  Scanner-ready            : {scanner_ready_count}")
    print(f"  Active-ready             : {active_ready_count}")
    print(f"  Product-ready            : {product_ready_count}")
    print(f"  Grades                   : {dict(counts)}")
    print(f"  Categories               : {dict(by_category)}")
    print()
    print("── Detection Quality (from first principles) ─────────────────")
    for k, v in detection_quality.items():
        bar = "█" * int(v * 50 // max(1, len(findings))) if isinstance(v, int) else ""
        print(f"  {k:<35}: {v}  {bar}")
    print()
    print(f"  JSON : {json_path}")
    print(f"  CSV  : {csv_path}")
    print("=" * 68)

    non_exp = [
        item for item in findings
        if not item.is_recon and item.grade != "EXP_READY"
    ]
    if non_exp:
        print(f"\nNon-EXP vulnerability plugins ({len(non_exp)}):")
        for item in non_exp[:80]:
            print(f"  - {item.file}: {item.grade}; missing={','.join(item.missing)}")
    if args.fail_on_non_exp and non_exp:
        return 2
    return 0


def _detection_quality_breakdown(pocs_dir: Path) -> dict:
    """Count scripts by detection quality level (A/B/C/D/HW).

    Detection levels (NIST-aligned):
      A – Behavioral: crash/exploit confirmed through active probe
      B – Functional payload: CVE-specific payload sent, response characterized
      C – Version+config: version fingerprinted via TLS/SSH/HTTP/ADB/wpa_supplicant
      D – Static/metadata: no active probe possible without hardware/device
      HW – Hardware required: BT/CAN/RF/WiFi NIC/nRF dongle needed
    """
    counts: dict[str, int] = {"A_behavioral": 0, "B_payload": 0, "C_version_config": 0,
                               "D_static": 0, "HW_hardware": 0}
    for py in sorted(pocs_dir.glob("**/*.py")):
        if not py.name[0].isdigit():
            continue
        txt = py.read_text(errors="ignore")
        has_crash   = bool(re.search(
            r"ConnectionResetError|worker_crashed|crashed.*True|Segmentation fault|"
            r"_crash_confirmed|uid=0|root shell|SIGABRT|exploited.*True",
            txt))
        has_payload = bool(re.search(
            r"sendall\(|s\.send\(|sock\.send|zipmap|hpack_bomb|pack_stuffing|overflow_path|"
            r"gcc.*-o|_compile_and_run|_webp_decoder_probe|_ffmpeg_probe",
            txt))
        has_active_tcp = bool(re.search(
            r"connect_ex\(|s\.recv\(|socket\.create_connection|paramiko\.SSHClient|"
            r"urllib\.request\.(urlopen|Request)|requests\.(get|post|put|delete|session)|"
            r"http\.client\.(HTTPConnection|HTTPSConnection)|HTTPProbe|adb\.shell\(|"
            r"list_adb_devices|adb_devices\(\)|adb pull|adb -s |via_adb|"
            r"subprocess.*adb.*shell|check_car_app_version|check_prerequisites.*adb|"
            r"adb_trigger|adb.*push|adb.*install|adb.*am start|\"adb\"|'adb'|"
            r"android_exposure\(|_adb_shell|wireless_cve_audit|execute_check_callable",
            txt))
        has_version = bool(re.search(
            r"version_in_range|version_in_affected_range|openssl_version_affected|"
            r"ssh_exec|ADBProbe|wpa_supplicant|hostapd.*version|detected_version|"
            r"gst-inspect|pkg-config.*version|ldd.*version|ffmpeg.*version",
            txt))
        has_hw      = bool(re.search(
            r"nRF52840|sweyntooth|AF_CAN|can_bus_utils|SDR|rtl_sdr|hackrf|"
            r"wireshark|monitor mode|BTLE_|BroadcastSlave|hcitool scan|"
            r"wdissector|braktooth|BrakTooth|ESP32.*driver|esp32_driver|"
            r"scapy.*BLE|target_bdaddr|bluetooth_mac.*dongle|"
            r"interface.*monitor|iw.*monitor|airmon|tcpdump.*wlan|"
            r"wlan0mon|fragattack|FRAG_SCRIPT|monitor_mode|"
            r"target_bssid|inject.*control.*client|KRACK_SCRIPT|",
            txt))
        if has_crash:
            counts["A_behavioral"] += 1
        elif has_payload:
            counts["B_payload"] += 1
        elif has_version or has_active_tcp:
            counts["C_version_config"] += 1
        elif has_hw:
            counts["HW_hardware"] += 1
        else:
            counts["D_static"] += 1
    total = sum(counts.values())
    counts["total"] = total
    counts["product_quality_pct"] = round(
        100 * (counts["A_behavioral"] + counts["B_payload"] + counts["C_version_config"]) / max(1, total), 1
    )
    return counts


if __name__ == "__main__":
    raise SystemExit(main())

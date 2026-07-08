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
    "REMOTE_ACTIVE": 4,
    "LAB_EXP": 5,
    "AUTO_EXP": 6,
}

ATTACK_INPUT_RE = re.compile(
    r"active_payload_(?:text|hex)|sample_path|_write_.*sample|payload\s*=|"
    r"payload_bytes|crafted|malformed|overflow|traversal|injection|replay|"
    r"evil|sqli|xss|intent|content://|service call|am start",
    re.IGNORECASE,
)
EXECUTION_RE = re.compile(
    r"sendall\(|\.send\(|requests\.(?:post|put|delete|get)\(|"
    r"bus\.send\(|subprocess\.run\(|socket\.create_connection\(|"
    r"adb|nmap|scapy|bluetooth|hcitool|l2ping",
    re.IGNORECASE,
)
EXP_EXECUTION_RE = re.compile(
    r"sendall\(|requests\.(?:post|put|delete)\(|bus\.send\(|"
    r"active_payload_(?:text|hex)|sample_path|_write_.*sample|"
    r"adb.+(?:am start|am broadcast|content query|content call|service call|input text)|"
    r"subprocess\.run\([^)]*(?:am|content|service|hcitool|l2ping|ffmpeg|chromium|decoder)",
    re.IGNORECASE | re.DOTALL,
)
OBSERVATION_RE = re.compile(
    r"vulnerable|phenomenon|crash|asan|heap|segmentation fault|reset|"
    r"unauthorized|sensitive|leak|disclosure|state change|manual|"
    r"requires_manual_review|operator_action|response_excerpt|after|before",
    re.IGNORECASE,
)
SAFETY_GATE_RE = re.compile(
    r"allow_disruptive|is_disruptive\s*=\s*True|meta_destructive_level\s*=\s*['\"]"
    r"(Restart|DataLoss|Brick|Disruptive|Probe)['\"]|requires_manual_review|manual_confirmation",
    re.IGNORECASE,
)
LAB_HARNESS_RE = re.compile(
    r"exp_profile|active_payload_param|operator_payload_param|operator_supplied_lab_payload|"
    r"operator_observation|build_local_sample_probe|run_local_target|probe\s*=",
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
    inherited_harness = "IVIVulnerabilityPlugin" in source and "def exploit" in source
    return not bool(EXP_EXECUTION_RE.search(source) or LAB_HARNESS_RE.search(source) or inherited_harness)


def _professional_classification(
    path: Path,
    source: str,
    meta: dict[str, Any],
    *,
    is_recon: bool,
    framework_payload: bool,
    framework_harness: bool,
    inherited_harness: bool,
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
    if re.search(r"active_payload_param|operator_payload_param|lab_payload_param|generic_exp_payload", source, re.I):
        evidence.append("operator_payload")
    if not evidence:
        evidence.append("metadata")

    native_execution = bool(re.search(r"sendall\(|bus\.send\(|requests\.(?:post|put|delete)\(|subprocess\.run\(", source, re.I))
    native_observation = bool(re.search(r"crash|reset|unauthorized|shell|vulnerable\s*:\s*True|before|after|returncode", source, re.I))
    has_local_lab_probe = bool(re.search(r"build_local_sample_probe|run_local_target|sample_path|_write_.*sample", source, re.I))
    has_operator_payload = bool(re.search(r"active_payload_param|operator_payload_param|lab_payload_param|operator_observation", source, re.I))
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
    elif config_or_version_audit and not (framework_payload or framework_harness or has_local_lab_probe or has_operator_payload):
        tier = "AUTHENTICATED_CONFIG" if "authenticated_config" in evidence else "PASSIVE"
        confidence = 75 if tier == "AUTHENTICATED_CONFIG" else 60
        safety = "safe"
        capability = "supported_harness" if inherited_harness else "none"
    elif framework_payload or has_local_lab_probe or has_operator_payload or framework_harness:
        tier = "LAB_EXP"
        confidence = 90 if has_local_lab_probe else 85
        safety = "destructive_lab_only" if is_disruptive or destructive_level in {"disruptive", "restart", "dataloss", "brick"} else "intrusive"
        capability = "operator_supplied" if has_operator_payload else "supported_harness"
    elif native_execution and native_observation and not run_active_wrapper and not config_or_version_audit and ("crafted_payload" in evidence or "crash_observed" in evidence):
        tier = "AUTO_EXP" if is_disruptive or destructive_level in {"disruptive", "restart", "dataloss", "brick"} else "REMOTE_ACTIVE"
        confidence = 100 if tier == "AUTO_EXP" else 95
        safety = "destructive_lab_only" if tier == "AUTO_EXP" else "intrusive"
        capability = "native_verified"
    elif "run_active_validation(" in source or protocol in {"http", "https", "http2", "redis", "airplay", "rtsp", "tcp"}:
        tier = "ACTIVE_PROBE"
        confidence = 70
        safety = "low_impact"
        capability = "supported_harness" if inherited_harness else "none"
    elif static_audit or "audit" in name.lower() or category in {"application", "advanced", "network", "wireless", "canbus"}:
        tier = "AUTHENTICATED_CONFIG" if "authenticated_config" in evidence or any(p in profiles for p in ("usb_adb", "local_artifact")) else "PASSIVE"
        confidence = 75 if tier == "AUTHENTICATED_CONFIG" else 60
        safety = "safe"
        capability = "supported_harness" if inherited_harness else "none"
    else:
        tier = "PASSIVE"
        confidence = 50
        safety = "safe"
        capability = "supported_harness" if inherited_harness else "none"

    if tier in {"PASSIVE", "AUTHENTICATED_CONFIG", "ACTIVE_PROBE"} and inherited_harness:
        capability = "supported_harness"

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
        re.search(r"active_payload_(?:text|hex)", source)
    )
    framework_harness = "run_active_validation(" in source and bool(LAB_HARNESS_RE.search(source))
    inherited_harness = "IVIVulnerabilityPlugin" in source and "def exploit" in source
    attack_input = (bool(ATTACK_INPUT_RE.search(source)) or framework_payload or framework_harness or inherited_harness) and not static_audit
    execution_path = (bool(EXP_EXECUTION_RE.search(source)) or framework_payload or framework_harness or inherited_harness) and not static_audit
    observable_result = (bool(OBSERVATION_RE.search(source)) or framework_payload or framework_harness or inherited_harness) and not static_audit
    professional = _professional_classification(
        path,
        source,
        meta,
        is_recon=is_recon,
        framework_payload=framework_payload,
        framework_harness=framework_harness,
        inherited_harness=inherited_harness,
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
        safety_gate=bool(SAFETY_GATE_RE.search(source) or inherited_harness),
        is_recon=is_recon,
        missing=[],
        validation_tier=professional["validation_tier"],
        detection_confidence=professional["detection_confidence"],
        execution_safety=professional["execution_safety"],
        evidence_basis=professional["evidence_basis"],
        exp_capability=professional["exp_capability"],
        professional_grade=professional["professional_grade"],
        not_native_exp=professional["not_native_exp"],
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
    json_path, csv_path = write_reports(findings, args.prefix)
    print(f"Audited {len(findings)} plugin files")
    print(f"Grades: {dict(counts)}")
    print(f"Categories: {dict(by_category)}")
    print(f"JSON: {json_path}")
    print(f"CSV: {csv_path}")
    non_exp = [
        item for item in findings
        if not item.is_recon and item.grade != "EXP_READY"
    ]
    if non_exp:
        print(f"Non-EXP vulnerability plugins: {len(non_exp)}")
        for item in non_exp[:80]:
            print(f"- {item.file}: {item.grade}; missing={','.join(item.missing)}")
    if args.fail_on_non_exp and non_exp:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

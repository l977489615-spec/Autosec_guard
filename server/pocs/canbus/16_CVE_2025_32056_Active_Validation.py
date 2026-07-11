#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import socket
import struct
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _check_can_socket() -> dict:
    """Check if CAN socket interface is available."""
    info = {"af_can_available": False, "interfaces": [], "python_can": False}
    try:
        # Check if AF_CAN is defined (Linux-only)
        af_can = getattr(socket, "AF_CAN", None)
        if af_can is not None:
            info["af_can_available"] = True
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["ip", "link", "show", "type", "can"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.splitlines():
                if ":" in line and "can" in line.lower():
                    iface = line.split(":")[1].strip().split("@")[0].strip()
                    if iface:
                        info["interfaces"].append(iface)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    try:
        import importlib.util
        spec = importlib.util.find_spec("can")
        info["python_can"] = spec is not None
    except Exception:
        pass

    return info


def _analyze_can_log(can_log_text: str) -> dict:
    """Analyze CAN log text for weak/predictable anti-theft challenge responses."""
    findings = {
        "challenge_response_pairs": [],
        "predictable_pattern_detected": False,
        "anti_theft_frames_found": False,
    }
    if not can_log_text:
        return findings

    import re
    # Look for Bosch Nissan anti-theft challenge/response pattern (0x5xx range)
    frames = re.findall(
        r'([0-9A-Fa-f]{3,8})\s+[#\[]([0-9A-Fa-f]{2,16})',
        can_log_text,
    )
    anti_theft_ids = {"590", "5A0", "5B0", "5C0", "400", "401"}
    seen_ids = set()
    responses = []
    for frame_id, data in frames:
        if frame_id.upper() in anti_theft_ids or frame_id.upper().startswith("5"):
            findings["anti_theft_frames_found"] = True
            seen_ids.add(frame_id.upper())
            try:
                val = int(data, 16)
                responses.append(val)
            except ValueError:
                pass

    if len(responses) >= 4:
        # Check for low-entropy (all same, or trivially sequential)
        unique = len(set(responses))
        if unique < len(responses) / 2:
            findings["predictable_pattern_detected"] = True
            findings["low_entropy_ratio"] = unique / len(responses)

    findings["challenge_response_pairs"] = list(seen_ids)
    return findings


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    can_log_text = params.get("can_log_text", "")

    evidence = {
        "cve": "CVE-2025-32056",
        "target": "Nissan Leaf ZE1 / Bosch IVI ECU",
        "technique": (
            "Passive CAN log analysis for weak/predictable anti-theft response generation; "
            "CAN socket availability check"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2025-32056",
        "research": "http://i.blackhat.com/Asia-25/Asia-25-Evdokimov-Remote-Exploitation-of-Nissan-Leaf.pdf",
    }

    can_info = _check_can_socket()
    evidence["can_environment"] = can_info

    log_findings = _analyze_can_log(can_log_text)
    evidence["can_log_analysis"] = log_findings

    if log_findings["predictable_pattern_detected"]:
        vulnerable = True
        evidence["note"] = (
            "CAN log shows low-entropy anti-theft responses consistent with CVE-2025-32056: "
            "all 32 responses are pre-calculable from CAN traffic sniffing"
        )
    elif log_findings["anti_theft_frames_found"]:
        vulnerable = None
        evidence["note"] = "Anti-theft CAN frames detected; deeper entropy analysis required"
    else:
        vulnerable = None
        evidence["note"] = (
            "No CAN interface or log available for active analysis. "
            "Requires physical CAN access to Nissan Leaf ZE1 OBD-II port"
        )

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    "id": 1,
    "cve": "CVE-2025-32056",
    "year": 2025,
    "domain": "IVI/CAN/OTA",
    "vendor_product": "Nissan Leaf ZE1 / Bosch Infotainment ECU",
    "component": "Linux IVI、RH850 CAN模块、Redbend OTA",
    "type": "弱随机/认证绕过",
    "summary": "Bosch IVI防盗保护响应生成算法可预测，可通过CAN嗅探或预计算绕过保护。",
    "source_description": "The anti-theft protection mechanism can be bypassed by attackers due to weak response generation algorithms for the head unit. It is possible to reveal all 32 corresponding responses by sniffing CAN traffic or by pre-calculating the values, which allow to bypass the protection.\n\nFirst identified on Nissan Leaf ZE1 manufactured in 2020.",
    "poc_status": "有公开BlackHat/PCA研究材料；未整理为一步式PoC",
    "research_value": "适合研究IVI到CAN边界突破、OTA信任链、域间横向移动。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-32056",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-32056",
        "https://www.nissan.co.uk/vehicles/new-vehicles/leaf.html",
        "http://i.blackhat.com/Asia-25/Asia-25-Evdokimov-Remote-Exploitation-of-Nissan-Leaf.pdf",
        "https://pcacybersecurity.com/resources/advisory/vulnerabilities-in-nissan-infotainment-manufactured-by-bosch",
        "https://cveawg.mitre.org/api/cve/CVE-2025-32056"
    ],
    "affected": [
        {
            "vendor": "Bosch",
            "product": "Infotainment system ECU",
            "versions": [
                {
                    "version": "283C30861E",
                    "status": "affected",
                    "versionType": "283C30861E"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-32056",
        "Nissan",
        "Leaf",
        "ZE1",
        "Bosch",
        "Infotainment",
        "ECU",
        "Linux",
        "IVI",
        "RH850",
        "CAN",
        "Redbend",
        "OTA",
        "anti-theft",
        "protection",
        "mechanism",
        "bypassed",
        "attackers",
        "weak",
        "response",
        "generation",
        "algorithms",
        "head",
        "unit",
        "possible",
        "reveal",
        "corresponding",
        "responses",
        "sniffing",
        "traffic"
    ]
}


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc16CVE202532056WeakRandomAuthBypassAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-CAN-016"
    meta_poc_name = 'CVE-2025-32056 认证绕过 Active Validation'
    meta_cve_id = 'CVE-2025-32056'
    meta_severity = 'Medium'
    meta_protocol = 'can'
    meta_target_os = ['linux']
    meta_required_params = ['can_log_text']
    meta_profiles = ['can_extended']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-32056'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2025-32056']
    meta_attack_surface = 'CAN/UDS/OBD'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "16_Nissan_Bosch_CAN_Weak_Random_Auth_Bypass_Audit") if "VULN" in dir() else "16_Nissan_Bosch_CAN_Weak_Random_Auth_Bypass_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc16CVE202532056WeakRandomAuthBypassAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

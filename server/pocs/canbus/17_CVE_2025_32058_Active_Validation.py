#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import socket
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _check_inc_interface(can_log_text: str) -> dict:
    """Check for INC protocol frames between IVI SoC and RH850 CAN module."""
    import re
    findings = {
        "inc_frames_found": False,
        "oversized_frame_detected": False,
        "suspected_overflow_frames": [],
    }
    if not can_log_text:
        return findings

    # INC protocol frames typically appear as extended CAN frames with specific IDs
    # or large payloads forwarded across IVI<->RH850 bridge
    frames = re.findall(r'([0-9A-Fa-f]{3,8})\s+[#\[]([0-9A-Fa-f]+)', can_log_text)
    for frame_id, data in frames:
        # INC frames from IVI to RH850 often use 0x7xx / 0x6xx ranges
        if frame_id.upper().startswith(("7", "6")) and len(data) >= 16:
            findings["inc_frames_found"] = True
            if len(data) > 24:
                findings["oversized_frame_detected"] = True
                findings["suspected_overflow_frames"].append(
                    {"id": frame_id, "data_len": len(data)}
                )
    return findings


def _check_can_environment() -> dict:
    """Check CAN interface availability and version info."""
    info = {"af_can_available": False, "can_interfaces": []}
    try:
        if getattr(socket, "AF_CAN", None) is not None:
            info["af_can_available"] = True
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["ip", "-o", "link", "show", "type", "can"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if ":" in line:
                    iface = line.split(":")[1].strip().split("@")[0].strip()
                    if iface:
                        info["can_interfaces"].append(iface)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return info


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    can_log_text = params.get("can_log_text", "")

    evidence = {
        "cve": "CVE-2025-32058",
        "target": "Nissan Leaf ZE1 / Bosch IVI ECU (INC protocol / RH850 module)",
        "technique": (
            "Passive analysis of CAN log for INC protocol oversized frames; "
            "checks for stack overflow trigger pattern in IVI-to-RH850 bridge"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2025-32058",
        "impact": "Attacker with IVI code exec can pivot to RH850 and send arbitrary CAN messages",
    }

    can_env = _check_can_environment()
    evidence["can_environment"] = can_env

    inc_findings = _check_inc_interface(can_log_text)
    evidence["inc_analysis"] = inc_findings

    if inc_findings["oversized_frame_detected"]:
        vulnerable = True
        evidence["note"] = (
            "Oversized INC frames detected in CAN log - potential stack overflow trigger; "
            f"suspect frames: {inc_findings['suspected_overflow_frames']}"
        )
    elif inc_findings["inc_frames_found"]:
        vulnerable = None
        evidence["note"] = "INC-like frames found; payload size within bounds but requires firmware analysis"
    else:
        vulnerable = None
        evidence["note"] = (
            "Requires physical access to Nissan Leaf ZE1 INC bus interface. "
            "Vulnerability exists in RH850 firmware processing of IVI SoC requests."
        )

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    "id": 3,
    "cve": "CVE-2025-32058",
    "year": 2025,
    "domain": "IVI/CAN/OTA",
    "vendor_product": "Nissan Leaf ZE1 / Bosch Infotainment ECU",
    "component": "Linux IVI、RH850 CAN模块、Redbend OTA",
    "type": "栈溢出/RCE",
    "summary": "IVI到RH850 CAN通信模块的自定义INC协议处理存在栈溢出，可扩展到CAN总线任意报文发送。",
    "source_description": "The Infotainment ECU manufactured by Bosch uses a RH850 module for CAN communication. RH850 is connected to infotainment over the INC interface through a custom protocol. There is a vulnerability during processing requests of this protocol on the V850 side which allows an attacker with code execution on the infotainment main SoC to perform code execution on the RH850 module and subsequently send arbitrary CAN messages over the connected CAN bus.\n\n\n\nFirst identified on Nissan Leaf ZE1 manufactured in 2020.",
    "poc_status": "有公开BlackHat/PCA研究材料；未整理为一步式PoC",
    "research_value": "适合研究IVI到CAN边界突破、OTA信任链、域间横向移动。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-32058",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-32058",
        "https://www.nissan.co.uk/vehicles/new-vehicles/leaf.html",
        "http://i.blackhat.com/Asia-25/Asia-25-Evdokimov-Remote-Exploitation-of-Nissan-Leaf.pdf",
        "https://pcacybersecurity.com/resources/advisory/vulnerabilities-in-nissan-infotainment-manufactured-by-bosch",
        "https://cveawg.mitre.org/api/cve/CVE-2025-32058"
    ],
    "affected": [
        {
            "vendor": "Bosch",
            "product": "Infotainment system ECU",
            "versions": [
                {
                    "version": "283C30861E",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-32058",
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
        "RCE",
        "manufactured",
        "uses",
        "module",
        "communication",
        "connected",
        "infotainment",
        "over",
        "interface",
        "custom",
        "protocol",
        "There",
        "vulnerability",
        "during",
        "processing",
        "requests",
        "V850"
    ]
}


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc17CVE202532058StackOverflowRCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-003'
    meta_poc_name = 'CVE-2025-32058 RCE Active Validation'
    meta_cve_id = 'CVE-2025-32058'
    meta_severity = 'Critical'
    meta_protocol = 'can'
    meta_target_os = ['linux']
    meta_required_params = ['can_log_text']
    meta_profiles = ['can_extended']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-32058'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2025-32058']
    meta_attack_surface = 'CAN/UDS/OBD'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "17_Nissan_Bosch_INC_Stack_Overflow_RCE_Audit") if "VULN" in dir() else "17_Nissan_Bosch_INC_Stack_Overflow_RCE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc17CVE202532058StackOverflowRCEAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _probe_rkes_state_machine(wireless_scan_text: str) -> dict:
    """
    Probe for RKES protocol state machine vulnerabilities.
    CVE-2026-49318: Improper state transitions allow commands sent out-of-order
    to be accepted by the receiver (e.g., unlock without preceding valid auth).
    """
    findings = {
        "rkes_device_found": False,
        "state_machine_indicators": [],
        "rf_frequency_hints": [],
    }
    if not wireless_scan_text:
        return findings

    text_lower = wireless_scan_text.lower()
    rkes_terms = ["rkes", "remote keyless", "key entry", "uhf", "433", "315", "fob"]
    for term in rkes_terms:
        if term in text_lower:
            findings["rkes_device_found"] = True
            findings["rf_frequency_hints"].append(term)
            break

    # Look for state machine weakness indicators
    sm_terms = ["state", "sequence", "out-of-order", "replay", "command accepted"]
    for term in sm_terms:
        if term in text_lower:
            findings["state_machine_indicators"].append(term)

    return findings


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    wireless_scan_text = params.get("wireless_scan_text", "")

    evidence = {
        "cve": "CVE-2026-49318",
        "target": "RKES (Remote Keyless Entry System) protocol implementation",
        "technique": (
            "Passive audit: detect RKES device; verify protocol state machine by sending "
            "out-of-sequence RF commands (e.g., unlock command without auth frame)"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-49318",
        "attack_scenario": (
            "Attacker sends RKES 'unlock' command bypassing authentication state; "
            "improper state machine allows command acceptance without valid preceding auth"
        ),
        "test_steps": [
            "1. Capture RKES unlock frame via SDR at 433/315 MHz",
            "2. Craft out-of-sequence command (skip auth state)",
            "3. Transmit crafted frame and observe vehicle response",
            "4. Confirm state machine bypass if unlock occurs without valid auth",
        ],
    }

    sm_findings = _probe_rkes_state_machine(wireless_scan_text)
    evidence["rkes_analysis"] = sm_findings

    if sm_findings["rkes_device_found"]:
        vulnerable = None
        evidence["note"] = (
            "RKES device detected. Physical RF testing required to verify state machine bypass."
        )
    else:
        vulnerable = None
        evidence["note"] = (
            "No RKES device detected in scan. Physical access and SDR required for state machine audit."
        )

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": True,
    }


VULN = {
    "id": 12,
    "cve": "CVE-2026-49318",
    "year": 2026,
    "domain": "协议/RF/RKES",
    "vendor_product": "Automotive RF/RKES",
    "component": "Key fob / RF protocol",
    "type": "协议状态机缺陷",
    "summary": "远程无钥匙进入流程错误处理顺序与失败开放，影响认证安全。",
    "source_description": "Incorrect behavior order in the Infotainment / Digital Round display of the Indian Motorcycle Scout Bobber + Tech 2025 model year allows an adjacent-network attacker to bypass the PIN entry screen. The Infotainment uses presence of Wireless Control Module (WCM) traffic during its boot window as a proxy for whether an immobilizer is fitted; if no WCM messages are observed, it skips the PIN entry screen and shows the normal user interface. An attacker who silences the WCM during the boot window — for example via a separately tracked CAN bus-off technique — can present a fully unlocked Infotainment despite the PIN never being entered. Specific timing and protocol details have been withheld pending vendor remediation.",
    "poc_status": "有公开安全公告；部分有研究演示，未见通用武器化PoC",
    "research_value": "适合车钥匙RF协议、滚动码/回滚检测、防重放机制研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-49318",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-49318",
        "https://cwe.mitre.org/data/definitions/696.html",
        "https://cveawg.mitre.org/api/cve/CVE-2026-49318"
    ],
    "affected": [
        {
            "vendor": "Indian Motorcycle",
            "product": "Scout Bobber + Tech",
            "versions": [
                {
                    "version": "2025",
                    "status": "affected",
                    "versionType": "model-year"
                }

            ]
        }
    ],
    "signature_tokens": [
        "CVE-2026-49318",
        "Automotive",
        "RKES",
        "Key",
        "fob",
        "protocol",
        "Incorrect",
        "behavior",
        "order",
        "Infotainment",
        "Digital",
        "Round",
        "display",
        "Indian",
        "Motorcycle",
        "Scout",
        "Bobber",
        "Tech",
        "model",
        "year",
        "adjacent-network",
        "bypass",
        "entry",
        "screen",
        "uses",
        "presence",
        "Wireless",
        "Control",
        "Module",
        "traffic"
    ]
}

# ── 硬件需求（HW_REQUIREMENTS） ────────────────────────────────────────
HW_REQUIREMENTS = {
    "hardware":   ['Yard Stick One 或 HackRF One', 'RKE 天线（315 MHz / 433.92 MHz）'],
    "connection": 'USB',
    "tools":      ['RFCat（Yard Stick）或 GNU Radio', 'URH / inspectrum'],
    "firmware":   'RFCat firmware（yardstickone.com）',
    "setup":      'rfcat -r && d.setFreq(433920000)',
}



try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc38CVE202649318ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-012'
    meta_poc_name = 'CVE-2026-49318 协议状态机缺陷 Active Validation'
    meta_cve_id = 'CVE-2026-49318'
    meta_severity = 'High'
    meta_protocol = 'rf'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['rf']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2026-49318'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2026-49318']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "38_RKES_Protocol_State_Machine_Audit") if "VULN" in dir() else "38_RKES_Protocol_State_Machine_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc38CVE202649318ExposureAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

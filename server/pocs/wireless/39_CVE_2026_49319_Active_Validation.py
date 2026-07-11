#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _check_suzuki_rkes(wireless_scan_text: str) -> dict:
    """Detect Suzuki Swift RKES indicators and check for replay vulnerability."""
    findings = {
        "suzuki_detected": False,
        "rkes_detected": False,
        "rolling_code_present": False,
        "indicators": [],
    }
    if not wireless_scan_text:
        return findings

    text_lower = wireless_scan_text.lower()
    if "suzuki" in text_lower or "swift" in text_lower:
        findings["suzuki_detected"] = True
        findings["indicators"].append("suzuki/swift device mentioned")
    if any(t in text_lower for t in ("rkes", "keyless", "remote key", "433", "315")):
        findings["rkes_detected"] = True
        findings["indicators"].append("RKES/RF frequency detected")
    if any(t in text_lower for t in ("rolling", "keeloq", "hopping code")):
        findings["rolling_code_present"] = True
        findings["indicators"].append("rolling code mentioned")
    return findings


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    wireless_scan_text = params.get("wireless_scan_text", "")

    evidence = {
        "cve": "CVE-2026-49319",
        "target": "Suzuki Swift RKES - replay vulnerability",
        "technique": (
            "RF replay audit: capture Suzuki Swift key fob transmission, "
            "replay captured frame to test absence of anti-replay counter"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-49319",
        "attack_scenario": (
            "Attacker captures RKES unlock frame via SDR and replays it later "
            "to unlock Suzuki Swift without physical key fob"
        ),
        "test_methodology": [
            "1. Position SDR receiver near Suzuki Swift key fob (433.92 MHz)",
            "2. Record IQ samples when owner presses unlock button",
            "3. Save frame and replay using hackrf_transfer or URH",
            "4. Observe if vehicle responds to replayed frame (confirms no replay counter)",
        ],
    }

    findings = _check_suzuki_rkes(wireless_scan_text)
    evidence["rkes_scan_analysis"] = findings

    if findings["suzuki_detected"] and findings["rkes_detected"]:
        if not findings["rolling_code_present"]:
            vulnerable = True
            evidence["note"] = (
                "Suzuki Swift RKES detected without rolling code protection - replay attack viable"
            )
        else:
            vulnerable = None
            evidence["note"] = "Rolling code mentioned; verify actual implementation strength"
    elif findings["rkes_detected"]:
        vulnerable = None
        evidence["note"] = "RKES detected but Suzuki not confirmed; physical test required"
    else:
        vulnerable = None
        evidence["note"] = (
            "No Suzuki Swift RKES detected. Physical proximity to vehicle required."
        )

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    "id": 13,
    "cve": "CVE-2026-49319",
    "year": 2026,
    "domain": "协议/RF/RKES",
    "vendor_product": "Suzuki Swift 2024 RKES",
    "component": "Key fob / RF protocol",
    "type": "重放攻击",
    "summary": "RKES回滚/重放攻击，可利用旧帧绕过认证。",
    "source_description": "Remote Keyless Entry System (RKES), using the 433 MHz key fob bearing FCC ID CWTR53R0 manufactured by ALPS ALPINE CO., LTD., is vulnerable to a roll-back attack against its rolling-code authentication. \n\n\n\nAn attacker within RF range who records two consecutive lock or unlock transmissions from a legitimate key fob can later replay the same pair of transmissions repeatedly. During testing, replaying the first captured transmission caused the RKES to enter a state in which replaying the second captured transmission resulted in a successful lock or unlock operation of the vehicle. Tested and confirmed on a 2024 Suzuki Swift (SWIFT ISG GLS AC 1.2 5P 4x2 TM).",
    "poc_status": "有公开安全公告；部分有研究演示，未见通用武器化PoC",
    "research_value": "适合车钥匙RF协议、滚动码/回滚检测、防重放机制研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-49319",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-49319",
        "https://fccid.io/CWTR53R0",
        "https://www.asrg.io/security-advisories/cve-2026-49319-suzuki-swift-2024-rkes-rollback-replay",
        "https://cveawg.mitre.org/api/cve/CVE-2026-49319"
    ],
    "affected": [
        {
            "vendor": "Alps Electric Co., Ltd.",
            "product": "Remote Keyless Entry System (RKES) R53R0",
            "versions": [
                {
                    "version": "R53R0",
                    "status": "affected",
                    "versionType": "custom"
                }

            ]
        }
    ],
    "signature_tokens": [
        "CVE-2026-49319",
        "Suzuki",
        "Swift",
        "RKES",
        "Key",
        "fob",
        "protocol",
        "Remote",
        "Keyless",
        "Entry",
        "System",
        "using",
        "bearing",
        "CWTR53R0",
        "manufactured",
        "ALPS",
        "ALPINE",
        "LTD",
        "vulnerable",
        "roll-back",
        "attack",
        "against",
        "rolling-code",
        "authentication",
        "within",
        "range",
        "records",
        "consecutive",
        "lock",
        "unlock"
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

class Poc39CVE202649319ReplayAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-039"
    meta_poc_name = 'CVE-2026-49319 重放攻击 Active Validation'
    meta_cve_id = 'CVE-2026-49319'
    meta_severity = 'High'
    meta_protocol = 'rf'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['rf']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2026-49319'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2026-49319']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "39_Suzuki_Swift_RKES_Replay_Audit") if "VULN" in dir() else "39_Suzuki_Swift_RKES_Replay_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc39CVE202649319ReplayAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _check_rf_replay_tooling() -> dict:
    """Check for replay attack tooling availability."""
    tools = {}
    for tool in ("rtl_433", "hackrf_transfer", "urh", "rfcat", "gnuradio-companion"):
        try:
            r = subprocess.run(["which", tool], capture_output=True, text=True, timeout=3)
            tools[tool] = r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            tools[tool] = False
    return tools


def _analyze_scan_for_replay_indicators(scan_text: str) -> dict:
    """Detect absence of rolling code / anti-replay mechanism indicators."""
    findings = {
        "rolling_code_mentioned": False,
        "fixed_code_indicators": [],
        "ke700_present": False,
    }
    if not scan_text:
        return findings
    text_lower = scan_text.lower()
    if "rolling" in text_lower or "keeloq" in text_lower or "hopping" in text_lower:
        findings["rolling_code_mentioned"] = True
    if "ke700" in text_lower or "micca" in text_lower:
        findings["ke700_present"] = True
    # Fixed code indicators
    for pattern in ("fixed code", "static code", "no rolling", "plaintext", "cleartext"):
        if pattern in text_lower:
            findings["fixed_code_indicators"].append(pattern)
    return findings


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    wireless_scan_text = params.get("wireless_scan_text", "")

    evidence = {
        "cve": "CVE-2026-2540",
        "target": "Micca KE700 car alarm - auth bypass via RF replay",
        "technique": (
            "Passive audit: check for replay attack tooling, verify absence of rolling code "
            "in KE700 RF protocol; replay captured frames via SDR"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-2540",
        "attack_steps": [
            "1. Capture key fob RF frame at 433.92 MHz using RTL-SDR / HackRF",
            "2. Save IQ samples containing alarm disarm command",
            "3. Replay saved frame using hackrf_transfer or URH",
            "4. KE700 accepts replayed frame due to absent rolling code anti-replay",
        ],
    }

    tools = _check_rf_replay_tooling()
    evidence["replay_tools"] = tools

    scan_findings = _analyze_scan_for_replay_indicators(wireless_scan_text)
    evidence["scan_analysis"] = scan_findings

    if scan_findings["fixed_code_indicators"] or (
        scan_findings["ke700_present"] and not scan_findings["rolling_code_mentioned"]
    ):
        vulnerable = True
        evidence["note"] = "Indicators suggest fixed-code / no rolling code - replay attack viable"
    elif scan_findings["ke700_present"]:
        vulnerable = None
        evidence["note"] = "KE700 detected; manual RF capture required to verify replay protection"
    else:
        vulnerable = None
        evidence["note"] = (
            "No KE700 detected in scan. Physical proximity + SDR required for RF replay test."
        )

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    "id": 10,
    "cve": "CVE-2026-2540",
    "year": 2026,
    "domain": "协议/RF/RKES",
    "vendor_product": "Micca KE700 car alarm",
    "component": "Key fob / RF protocol",
    "type": "认证绕过/重放",
    "summary": "车载报警系统存在备用路径/重放导致认证绕过。",
    "source_description": "The Micca KE700 system contains flawed resynchronization logic and is vulnerable to replay attacks. This attack requires sending two previously captured codes in a specific sequence. As a result, the system can be forced to accept previously used (stale) rolling codes and execute a command. Successful exploitation allows an attacker to clone the alarm key. This grants the attacker unauthorized access to the vehicle to unlock or lock the doors.",
    "poc_status": "有公开安全公告；部分有研究演示，未见通用武器化PoC",
    "research_value": "适合车钥匙RF协议、滚动码/回滚检测、防重放机制研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-2540",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-2540",
        "https://asrg.io/security-advisories/cve-2026-2540/",
        "https://cveawg.mitre.org/api/cve/CVE-2026-2540"
    ],
    "affected": [
        {
            "vendor": "Micca Auto Electronics Co., Ltd.",
            "product": "Car Alarm System KE700",
            "versions": [
                {
                    "version": "KE700",
                    "status": "affected"
                }
,
                {
                    "version": "KE700+",
                    "status": "unknown"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2026-2540",
        "Micca",
        "KE700",
        "car",
        "alarm",
        "Key",
        "fob",
        "protocol",
        "system",
        "contains",
        "flawed",
        "resynchronization",
        "logic",
        "vulnerable",
        "replay",
        "attacks",
        "attack",
        "requires",
        "sending",
        "previously",
        "captured",
        "codes",
        "specific",
        "sequence",
        "result",
        "forced",
        "accept",
        "used",
        "stale",
        "rolling"
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

class Poc36CVE20262540AuthBypassReplayAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-036"
    meta_poc_name = 'CVE-2026-2540 重放 Active Validation'
    meta_cve_id = 'CVE-2026-2540'
    meta_severity = 'High'
    meta_protocol = 'rf'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['rf']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2026-2540'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2026-2540']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "36_Micca_KE700_RF_Auth_Bypass_Replay_Audit") if "VULN" in dir() else "36_Micca_KE700_RF_Auth_Bypass_Replay_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc36CVE20262540AuthBypassReplayAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

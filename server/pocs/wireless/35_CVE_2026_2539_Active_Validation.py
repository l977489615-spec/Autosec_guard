#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _check_rf_tools() -> dict:
    """Check if SDR or RF analysis tools are available."""
    tools = {}
    for tool in ("rtl_sdr", "hackrf_info", "gqrx", "urh", "rfcat", "python3"):
        try:
            r = subprocess.run(
                ["which", tool], capture_output=True, text=True, timeout=3
            )
            tools[tool] = r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            tools[tool] = False
    return tools


def _analyze_wireless_scan_for_rf(wireless_scan_text: str, keywords: list) -> dict:
    """Search wireless scan output for RF-related indicators."""
    findings = {
        "rf_device_found": False,
        "matched_keywords": [],
        "raw_excerpt": "",
    }
    if not wireless_scan_text:
        return findings
    text_lower = wireless_scan_text.lower()
    for kw in keywords:
        if kw.lower() in text_lower:
            findings["matched_keywords"].append(kw)
    if findings["matched_keywords"]:
        findings["rf_device_found"] = True
        # Extract a short excerpt around first match
        idx = text_lower.find(findings["matched_keywords"][0].lower())
        findings["raw_excerpt"] = wireless_scan_text[max(0, idx - 50): idx + 150]
    return findings


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    wireless_scan_text = params.get("wireless_scan_text", "")

    evidence = {
        "cve": "CVE-2026-2539",
        "target": "Micca KE700 car alarm / key fob RF module",
        "technique": (
            "Passive RF audit: check for SDR tools, scan for KE700 RF device indicators, "
            "verify absence of encryption in RF communication frames"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-2539",
        "vuln_detail": "RF frames transmitted in cleartext; random number + counter leaked via SDR capture",
    }

    rf_tools = _check_rf_tools()
    evidence["rf_tools"] = rf_tools

    rf_keywords = ["ke700", "micca", "433", "315mhz", "keyfob", "key fob", "rolling", "rke"]
    scan_findings = _analyze_wireless_scan_for_rf(wireless_scan_text, rf_keywords)
    evidence["wireless_scan_analysis"] = scan_findings

    has_sdr = any(rf_tools.get(t) for t in ("rtl_sdr", "hackrf_info", "urh", "rfcat"))
    evidence["sdr_capable"] = has_sdr

    if scan_findings["rf_device_found"]:
        vulnerable = None
        evidence["note"] = (
            f"KE700/RF indicators found in scan: {scan_findings['matched_keywords']}. "
            "Use SDR (RTL-SDR/HackRF) at 433.92 MHz to capture key fob transmissions and "
            "verify plaintext credential exposure."
        )
    else:
        vulnerable = None
        evidence["note"] = (
            "No KE700 RF device detected in scan data. "
            "Physical proximity and SDR hardware required to capture 433 MHz RF frames."
        )

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": True,
    }


VULN = {
    "id": 9,
    "cve": "CVE-2026-2539",
    "year": 2026,
    "domain": "协议/RF/RKES",
    "vendor_product": "Micca KE700 car alarm",
    "component": "Key fob / RF protocol",
    "type": "协议明文/认证材料泄露",
    "summary": "RF通信帧未加密，SDR可截获认证相关随机数/计数器。",
    "source_description": "The RF communication protocol in the Micca KE700 car alarm system does not encrypt its data frames. An attacker with a radio interception tool (e.g., SDR) can capture the random number and counters transmitted in cleartext, which is sensitive information required for authentication.",
    "poc_status": "有公开安全公告；部分有研究演示，未见通用武器化PoC",
    "research_value": "适合车钥匙RF协议、滚动码/回滚检测、防重放机制研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-2539",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-2539",
        "https://asrg.io/security-advisories/cve-2026-2539-micca-ke700-cleartext-transmission-of-key-fob-id/",
        "https://cveawg.mitre.org/api/cve/CVE-2026-2539"
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
        "CVE-2026-2539",
        "Micca",
        "KE700",
        "car",
        "alarm",
        "Key",
        "fob",
        "protocol",
        "communication",
        "system",
        "does",
        "encrypt",
        "data",
        "frames",
        "radio",
        "interception",
        "tool",
        "e.g",
        "capture",
        "random",
        "number",
        "counters",
        "transmitted",
        "cleartext",
        "which",
        "sensitive",
        "information",
        "required",
        "authentication",
        "Micca Auto Electronics Co., Ltd"
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

class Poc35CVE20262539ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-035"
    meta_poc_name = 'CVE-2026-2539 认证材料泄露 Active Validation'
    meta_cve_id = 'CVE-2026-2539'
    meta_severity = 'High'
    meta_protocol = 'rf'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['rf']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2026-2539'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2026-2539']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "35_Micca_KE700_RF_Plaintext_Credential_Leak_Audit") if "VULN" in dir() else "35_Micca_KE700_RF_Plaintext_Credential_Leak_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc35CVE20262539ExposureAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

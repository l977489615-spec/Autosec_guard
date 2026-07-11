#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import subprocess
import time

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _check_rf_burst_capability() -> dict:
    """Check for SDR hardware capable of rapid RF burst transmission."""
    tools = {}
    for tool in ("hackrf_transfer", "urh", "rfcat", "yardstick_one"):
        try:
            r = subprocess.run(["which", tool], capture_output=True, text=True, timeout=3)
            tools[tool] = r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            tools[tool] = False
    return tools


def _analyze_rate_limit_evidence(wireless_scan_text: str) -> dict:
    """Look for rate limiting / lockout indicators in RKES scan data."""
    findings = {
        "rkes_detected": False,
        "rate_limit_mentioned": False,
        "lockout_mentioned": False,
        "rapid_frame_indicators": [],
    }
    if not wireless_scan_text:
        return findings

    text_lower = wireless_scan_text.lower()
    if any(t in text_lower for t in ("rkes", "433", "315", "keyless")):
        findings["rkes_detected"] = True
    if any(t in text_lower for t in ("rate limit", "throttle", "lockout", "cooldown")):
        findings["rate_limit_mentioned"] = True
    if "lockout" in text_lower or "blocked" in text_lower:
        findings["lockout_mentioned"] = True

    # Detect burst/rapid frame patterns
    rapid_patterns = re.findall(
        r'(\d{3,})\s*(?:frames?|packets?|requests?)\s*/\s*(?:sec|second|min)',
        wireless_scan_text, re.IGNORECASE,
    )
    if rapid_patterns:
        findings["rapid_frame_indicators"] = rapid_patterns

    return findings


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    wireless_scan_text = params.get("wireless_scan_text", "")

    evidence = {
        "cve": "CVE-2026-49324",
        "target": "RKES protocol - missing authentication rate limiting",
        "technique": (
            "Passive audit: check for rate limiting / lockout mechanisms in RKES; "
            "verify system allows brute-force of authentication frames without lockout"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-49324",
        "vuln_detail": (
            "RKES receiver does not implement rate limiting or lockout after repeated "
            "failed authentication attempts, enabling brute-force of rolling codes"
        ),
        "brute_force_feasibility": {
            "code_space_16bit": 65536,
            "code_space_32bit": 4294967296,
            "frames_per_second_sdr": "~100-1000",
            "time_16bit_exhaustion": "~1 minute at 1000 fps",
        },
    }

    rf_tools = _check_rf_burst_capability()
    evidence["rf_burst_tools"] = rf_tools

    rate_findings = _analyze_rate_limit_evidence(wireless_scan_text)
    evidence["rate_limit_analysis"] = rate_findings

    if rate_findings["rkes_detected"]:
        if not rate_findings["rate_limit_mentioned"]:
            vulnerable = None
            evidence["note"] = (
                "RKES detected; no rate limiting evidence in scan. "
                "Physical test: transmit 100+ auth frames rapidly and check for lockout/blocking."
            )
        else:
            vulnerable = False
            evidence["note"] = "Rate limiting mechanism mentioned - may be patched"
    else:
        vulnerable = None
        evidence["note"] = "No RKES detected. SDR hardware needed for rate-limit brute-force test."

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    "id": 15,
    "cve": "CVE-2026-49324",
    "year": 2026,
    "domain": "协议/RF/RKES",
    "vendor_product": "Automotive RF/RKES",
    "component": "Key fob / RF protocol",
    "type": "认证节流不足",
    "summary": "认证尝试限制不足与资源消耗问题，可用于暴力/DoS。",
    "source_description": "Uncontrolled resource consumption in the Wireless Control Module (WCM) of the Indian Motorcycle Scout Bobber + Tech 2025 model year allows an adjacent-network attacker with write access to the in-vehicle network to permanently immobilize the motorcycle. The WCM enforces a brute-force lockout on the immobilizer authentication algorithm, but the lockout counter is reachable by any unauthenticated message, has no session binding, and does not reset on power cycle. An attacker can deliberately trip the lockout with a small number of crafted frames, leaving the bike un-startable until dealer service. Specific thresholds have been withheld pending vendor remediation.",
    "poc_status": "有公开安全公告；部分有研究演示，未见通用武器化PoC",
    "research_value": "适合车钥匙RF协议、滚动码/回滚检测、防重放机制研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-49324",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-49324",
        "https://www.asrg.io/security-advisories/cve-2026-49324-indian-scout-wcm-bruteforce-lockout-dos",
        "https://cveawg.mitre.org/api/cve/CVE-2026-49324"
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
        "CVE-2026-49324",
        "Automotive",
        "RKES",
        "Key",
        "fob",
        "protocol",
        "Uncontrolled",
        "resource",
        "consumption",
        "Wireless",
        "Control",
        "Module",
        "Indian",
        "Motorcycle",
        "Scout",
        "Bobber",
        "Tech",
        "model",
        "year",
        "adjacent-network",
        "write",
        "access",
        "in-vehicle",
        "network",
        "permanently",
        "immobilize",
        "motorcycle",
        "enforces",
        "brute-force",
        "lockout"
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

class Poc41CVE202649324ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-041"
    meta_poc_name = 'CVE-2026-49324 认证节流不足 Active Validation'
    meta_cve_id = 'CVE-2026-49324'
    meta_severity = 'High'
    meta_protocol = 'rf'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['rf']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2026-49324'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2026-49324']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "41_RKES_Auth_Rate_Limit_Audit") if "VULN" in dir() else "41_RKES_Auth_Rate_Limit_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc41CVE202649324ExposureAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

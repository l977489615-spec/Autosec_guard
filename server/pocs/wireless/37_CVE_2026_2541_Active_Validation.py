#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _check_rng_quality(scan_text: str) -> dict:
    """Check for low-entropy / weak PRNG indicators in scan output."""
    findings = {
        "ke700_present": False,
        "low_entropy_indicators": [],
        "sample_values": [],
    }
    if not scan_text:
        return findings
    text_lower = scan_text.lower()
    if "ke700" in text_lower or "micca" in text_lower:
        findings["ke700_present"] = True

    # Extract hex sequences that could be random numbers
    hex_vals = re.findall(r'\b([0-9a-fA-F]{4,8})\b', scan_text)
    if hex_vals:
        int_vals = [int(h, 16) for h in hex_vals[:20]]
        findings["sample_values"] = int_vals
        if len(int_vals) >= 4:
            # Simple low-entropy check: small range or repeated values
            value_range = max(int_vals) - min(int_vals)
            unique_ratio = len(set(int_vals)) / len(int_vals)
            if unique_ratio < 0.5 or value_range < 256:
                findings["low_entropy_indicators"].append(
                    f"low_unique_ratio={unique_ratio:.2f} range={value_range}"
                )

    for phrase in ("weak random", "low entropy", "pseudo-random", "linear congruential"):
        if phrase in text_lower:
            findings["low_entropy_indicators"].append(phrase)
    return findings


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    wireless_scan_text = params.get("wireless_scan_text", "")

    evidence = {
        "cve": "CVE-2026-2541",
        "target": "Micca KE700 car alarm - low entropy random number generation",
        "technique": (
            "Passive audit: analyze RF capture data for low-entropy PRNG patterns; "
            "statistical analysis of captured counter/random values"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-2541",
        "vuln_detail": (
            "KE700 uses a weak PRNG with insufficient entropy; "
            "predicted values allow attacker to pre-compute authentication tokens"
        ),
    }

    entropy_findings = _check_rng_quality(wireless_scan_text)
    evidence["entropy_analysis"] = entropy_findings

    if entropy_findings["low_entropy_indicators"]:
        vulnerable = True
        evidence["note"] = (
            f"Low-entropy indicators detected: {entropy_findings['low_entropy_indicators']}. "
            "KE700 PRNG output is predictable."
        )
    elif entropy_findings["ke700_present"]:
        vulnerable = None
        evidence["note"] = (
            "KE700 device detected. Capture multiple RF transmissions and apply "
            "statistical tests (NIST SP 800-22) to verify PRNG weakness."
        )
    else:
        vulnerable = None
        evidence["note"] = (
            "No KE700 detected. Requires SDR capture of multiple key fob transmissions "
            "to statistically analyze PRNG output entropy."
        )

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    "id": 11,
    "cve": "CVE-2026-2541",
    "year": 2026,
    "domain": "协议/RF/RKES",
    "vendor_product": "Micca KE700 car alarm",
    "component": "Key fob / RF protocol",
    "type": "熵不足",
    "summary": "随机数熵不足，降低射频认证强度。",
    "source_description": "The Micca KE700 system relies on a 6-bit portion of an identifier for authentication within rolling codes, providing only 64 possible combinations. This low entropy allows an attacker to perform a brute-force attack against one component of the rolling code. Successful exploitation simplify an attacker to predict the next valid rolling code, granting unauthorized access to the vehicle.",
    "poc_status": "有公开安全公告；部分有研究演示，未见通用武器化PoC",
    "research_value": "适合车钥匙RF协议、滚动码/回滚检测、防重放机制研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-2541",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-2541",
        "https://asrg.io/security-advisories/cve-2026-2541/",
        "https://cveawg.mitre.org/api/cve/CVE-2026-2541"
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
        "CVE-2026-2541",
        "Micca",
        "KE700",
        "car",
        "alarm",
        "Key",
        "fob",
        "protocol",
        "system",
        "relies",
        "portion",
        "identifier",
        "authentication",
        "within",
        "rolling",
        "codes",
        "providing",
        "only",
        "possible",
        "combinations",
        "entropy",
        "perform",
        "brute-force",
        "attack",
        "against",
        "component",
        "code",
        "Successful",
        "exploitation",
        "simplify"
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

class Poc37CVE20262541WeakRandomAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-011'
    meta_poc_name = 'CVE-2026-2541 熵不足 Active Validation'
    meta_cve_id = 'CVE-2026-2541'
    meta_severity = 'High'
    meta_protocol = 'rf'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['rf']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2026-2541'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2026-2541']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "37_Micca_KE700_RF_Low_Entropy_Audit") if "VULN" in dir() else "37_Micca_KE700_RF_Low_Entropy_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc37CVE20262541WeakRandomAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

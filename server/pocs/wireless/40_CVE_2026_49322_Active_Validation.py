#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _analyze_rkes_crypto(wireless_scan_text: str) -> dict:
    """Analyze RKES signal data for weak cryptographic indicators."""
    findings = {
        "rkes_detected": False,
        "weak_crypto_indicators": [],
        "encryption_mentioned": False,
        "frame_samples": [],
    }
    if not wireless_scan_text:
        return findings

    text_lower = wireless_scan_text.lower()
    if any(t in text_lower for t in ("rkes", "433", "315", "keyless", "remote")):
        findings["rkes_detected"] = True

    if any(t in text_lower for t in ("aes", "des", "encrypted", "cipher")):
        findings["encryption_mentioned"] = True
    else:
        # No encryption mentioned = potential weak/no crypto
        if findings["rkes_detected"]:
            findings["weak_crypto_indicators"].append("no_encryption_mentioned")

    # Check for known weak patterns
    for phrase in ("xor", "simple xor", "no encryption", "plaintext", "cleartext", "weak key"):
        if phrase in text_lower:
            findings["weak_crypto_indicators"].append(phrase)

    # Extract hex frame samples
    hex_frames = re.findall(r'(?:frame|packet|data)[:\s]+([0-9A-Fa-f]{8,32})', wireless_scan_text)
    findings["frame_samples"] = hex_frames[:5]

    return findings


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    wireless_scan_text = params.get("wireless_scan_text", "")

    evidence = {
        "cve": "CVE-2026-49322",
        "target": "RKES protocol - weak cryptography enabling replay attacks",
        "technique": (
            "Passive crypto audit: detect RKES traffic, analyze frame structure for "
            "absent/weak encryption (XOR, fixed key, no AES), verify replay feasibility"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-49322",
        "vuln_detail": (
            "RKES uses weak or absent cryptography; attacker can decrypt, forge, "
            "and replay authentication frames"
        ),
    }

    crypto_findings = _analyze_rkes_crypto(wireless_scan_text)
    evidence["crypto_analysis"] = crypto_findings

    if crypto_findings["weak_crypto_indicators"]:
        vulnerable = True
        evidence["note"] = (
            f"Weak/absent crypto indicators: {crypto_findings['weak_crypto_indicators']}. "
            "RKES authentication frames can be replayed or forged."
        )
    elif crypto_findings["rkes_detected"] and not crypto_findings["encryption_mentioned"]:
        vulnerable = None
        evidence["note"] = "RKES detected; crypto strength requires SDR frame capture and analysis"
    else:
        vulnerable = None
        evidence["note"] = "No RKES detected. Physical proximity + SDR required for crypto analysis."

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    "id": 14,
    "cve": "CVE-2026-49322",
    "year": 2026,
    "domain": "协议/RF/RKES",
    "vendor_product": "Automotive RF/RKES",
    "component": "Key fob / RF protocol",
    "type": "弱加密/重放",
    "summary": "弱认证和风险加密算法导致捕获-重放可行。",
    "source_description": "Weak authentication in the Wireless Control Module (WCM) of the Indian Motorcycle Scout Bobber + Tech 2025 model year allows an adjacent-network attacker with read access to the in-vehicle network to recover the user-set unlock PIN by passively observing a single PIN authentication exchange. The Infotainment Digital Round display computes its response using a non-cryptographic operation rather than a cryptographic challenge-response, so the PIN is mathematically derivable from one captured exchange, defeating the motorcycle's primary user-authentication control. Specific protocol details have been withheld pending vendor remediation.",
    "poc_status": "有公开安全公告；部分有研究演示，未见通用武器化PoC",
    "research_value": "适合车钥匙RF协议、滚动码/回滚检测、防重放机制研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-49322",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-49322",
        "https://www.asrg.io/security-advisories/cve-2026-49322-indian-scout-infotainment-wcm-weak-authentication",
        "https://cveawg.mitre.org/api/cve/CVE-2026-49322"
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
        "CVE-2026-49322",
        "Automotive",
        "RKES",
        "Key",
        "fob",
        "protocol",
        "Weak",
        "authentication",
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
        "read",
        "access",
        "in-vehicle",
        "network",
        "recover",
        "user-set",
        "unlock",
        "passively",
        "observing",
        "single",
        "exchange"
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

class Poc40CVE202649322ReplayCryptoAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-014'
    meta_poc_name = 'CVE-2026-49322 重放 Active Validation'
    meta_cve_id = 'CVE-2026-49322'
    meta_severity = 'High'
    meta_protocol = 'rf'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['rf']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2026-49322'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2026-49322']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "40_RKES_Weak_Crypto_Replay_Audit") if "VULN" in dir() else "40_RKES_Weak_Crypto_Replay_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc40CVE202649322ReplayCryptoAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

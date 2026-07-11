#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _check_sdr_tools() -> dict:
    """Check SDR tool availability for RF weak-random analysis."""
    tools = {}
    for tool in ("rtl_sdr", "hackrf_info", "urh", "rtl_433", "gnuradio-companion"):
        try:
            r = subprocess.run(["which", tool], capture_output=True, text=True, timeout=3)
            tools[tool] = r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            tools[tool] = False
    return tools


def _analyze_rf_entropy(wireless_scan_text: str) -> dict:
    """Analyze RF scan data for automotive key fob weak PRNG."""
    findings = {
        "automotive_rf_device": False,
        "frequency_hints": [],
        "weak_rng_indicators": [],
        "hex_samples": [],
    }
    if not wireless_scan_text:
        return findings

    text_lower = wireless_scan_text.lower()

    # Common automotive key fob frequencies
    for freq in ("433.92", "315", "433", "868", "906"):
        if freq in wireless_scan_text:
            findings["frequency_hints"].append(f"{freq} MHz")
            findings["automotive_rf_device"] = True

    # Automotive-related terms
    for term in ("key fob", "keyfob", "rke", "tire pressure", "tpms", "door unlock", "remote start"):
        if term in text_lower:
            findings["automotive_rf_device"] = True
            findings["frequency_hints"].append(term)

    # Extract hex sequences for entropy analysis
    hex_vals = re.findall(r'\b([0-9a-fA-F]{6,10})\b', wireless_scan_text)
    int_vals = [int(h, 16) for h in hex_vals[:20]]
    findings["hex_samples"] = hex_vals[:10]

    if len(int_vals) >= 4:
        unique = len(set(int_vals))
        val_range = max(int_vals) - min(int_vals) if int_vals else 0
        # Low entropy: many repeats or tiny range
        if unique < len(int_vals) * 0.5 or val_range < 0xFF:
            findings["weak_rng_indicators"].append(
                f"low_unique={unique}/{len(int_vals)} range={val_range}"
            )

    return findings


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    wireless_scan_text = params.get("wireless_scan_text", "")

    evidence = {
        "cve": "CVE-2024-6348",
        "target": "Generic Automotive RF / RKE system (key fob weak PRNG)",
        "technique": (
            "Passive RF entropy audit: detect automotive RF transmissions at 315/433 MHz, "
            "capture rolling codes, analyze PRNG output for low entropy / predictability"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-6348",
        "vuln_detail": (
            "Automotive RF key fob uses weak PRNG with insufficient entropy; "
            "attacker can predict future rolling codes by observing past transmissions"
        ),
    }

    sdr_tools = _check_sdr_tools()
    evidence["sdr_tools"] = sdr_tools

    entropy_findings = _analyze_rf_entropy(wireless_scan_text)
    evidence["rf_entropy_analysis"] = entropy_findings

    if entropy_findings["weak_rng_indicators"]:
        vulnerable = True
        evidence["note"] = (
            f"Weak PRNG detected: {entropy_findings['weak_rng_indicators']}. "
            "RF rolling code sequence is predictable."
        )
    elif entropy_findings["automotive_rf_device"]:
        vulnerable = None
        evidence["note"] = (
            "Automotive RF device detected. Capture 3+ consecutive key fob transmissions "
            "and apply NIST SP 800-22 statistical tests on the counter/random fields."
        )
    else:
        vulnerable = None
        evidence["note"] = (
            "No automotive RF device detected. SDR hardware required at 433.92 / 315 MHz."
        )

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    "id": 46,
    "cve": "CVE-2024-6348",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Automotive RF/protocol component",
    "component": "随机数/密钥材料",
    "type": "随机数不足",
    "summary": "随机值生成不足导致认证/加密材料强度下降。",
    "source_description": "Predictable seed generation in the security access mechanism of UDS in the Blind Spot Protection Sensor ECU in Nissan Altima (2022) allows attackers to predict the requested seeds and bypass security controls via repeated ECU resets and seed requests.",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6348",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-6348",
        "https://asrg.io/security-advisories/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-6348"
    ],
    "affected": [
        {
            "vendor": "Nissan",
            "product": "Altima",
            "versions": [
                {
                    "version": "Altima 2022",
                    "status": "unknown"
                }

            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-6348",
        "Automotive",
        "protocol",
        "component",
        "Predictable",
        "seed",
        "generation",
        "security",
        "access",
        "mechanism",
        "Blind",
        "Spot",
        "Protection",
        "Sensor",
        "Nissan",
        "Altima",
        "attackers",
        "predict",
        "requested",
        "seeds",
        "bypass",
        "controls",
        "repeated",
        "resets",
        "requests"
    ]
}

# ── 硬件需求（HW_REQUIREMENTS） ────────────────────────────────────────
HW_REQUIREMENTS = {
    "hardware":   ['HackRF One（19 MHz–6 GHz）或 RTL-SDR v3', '315/433 MHz 天线'],
    "connection": 'USB（libhackrf / rtl-sdr）',
    "tools":      ['GNU Radio ≥ 3.9', 'gr-osmosdr', 'URH（Universal Radio Hacker）'],
    "firmware":   'HackRF firmware ≥ 2021.03.1（hackrf_update）',
    "setup":      'hackrf_info && urh',
}



try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc48CVE20246348ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-048"
    meta_poc_name = 'CVE-2024-6348 随机数不足 Active Validation'
    meta_cve_id = 'CVE-2024-6348'
    meta_severity = 'Medium'
    meta_protocol = 'rf'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['rf']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-6348'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-6348']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "48_Automotive_RF_Weak_Random_Audit") if "VULN" in dir() else "48_Automotive_RF_Weak_Random_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc48CVE20246348ExposureAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

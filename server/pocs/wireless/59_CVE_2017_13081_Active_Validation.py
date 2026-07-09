#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _check_igtk_support() -> dict:
    """Check for IEEE 802.11w MFP (Management Frame Protection) and IGTK support."""
    info = {
        "wpa_supplicant_version": "",
        "mfp_configured": None,
        "igtk_krack_vulnerable": None,
    }
    try:
        r = subprocess.run(
            ["wpa_supplicant", "-v"],
            capture_output=True, text=True, timeout=5,
        )
        version_text = (r.stdout + r.stderr).strip()
        info["wpa_supplicant_version"] = version_text[:200]
        m = re.search(r'wpa_supplicant v?(\d+)\.(\d+)', version_text, re.IGNORECASE)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            # CVE-2017-13081: IGTK reinstall, fixed in wpa_supplicant 2.7
            info["igtk_krack_vulnerable"] = major < 2 or (major == 2 and minor < 7)
    except FileNotFoundError:
        info["error"] = "wpa_supplicant not found"
    except subprocess.TimeoutExpired:
        info["error"] = "timeout"

    # Check MFP configuration
    try:
        r = subprocess.run(
            ["cat", "/etc/wpa_supplicant/wpa_supplicant.conf"],
            capture_output=True, text=True, timeout=3,
        )
        conf = r.stdout.lower()
        if "ieee80211w" in conf or "mfp" in conf:
            info["mfp_configured"] = True
            if "ieee80211w=2" in conf:
                info["mfp_required"] = True
            else:
                info["mfp_required"] = False
        else:
            info["mfp_configured"] = False
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        info["mfp_config_check"] = "unavailable"

    return info


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    target_bssid = params.get("target_bssid", params.get("bssid", ""))

    evidence = {
        "cve": "CVE-2017-13081",
        "target": target_bssid or "WPA2 AP with 802.11w MFP (KRACK IGTK reinstall)",
        "technique": (
            "KRACK IGTK reinstall audit: check wpa_supplicant version, "
            "verify 802.11w MFP configuration, detect IGTK key reinstallation exposure"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-13081",
        "vuln_detail": (
            "KRACK: IGTK (Integrity Group Temporal Key) reinstallation in 4-way handshake. "
            "Affects devices using 802.11w Management Frame Protection."
        ),
        "krack_type": "IGTK reinstall in 4-way handshake (802.11w MFP)",
    }

    igtk_info = _check_igtk_support()
    evidence["igtk_analysis"] = igtk_info

    if igtk_info.get("igtk_krack_vulnerable") is True:
        if igtk_info.get("mfp_configured"):
            vulnerable = True
            evidence["note"] = (
                f"wpa_supplicant {igtk_info['wpa_supplicant_version']} is KRACK-vulnerable "
                "AND 802.11w MFP is configured. IGTK reinstall attack is applicable."
            )
        else:
            vulnerable = False
            evidence["note"] = (
                "wpa_supplicant is KRACK-vulnerable but 802.11w MFP not configured; "
                "IGTK reinstall not applicable without MFP."
            )
    elif igtk_info.get("igtk_krack_vulnerable") is False:
        vulnerable = False
        evidence["note"] = "wpa_supplicant patched for CVE-2017-13081 IGTK reinstall"
    else:
        vulnerable = None
        evidence["note"] = (
            "Cannot determine IGTK KRACK exposure. "
            "Check wpa_supplicant version and 802.11w MFP configuration on target."
        )

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    "id": 74,
    "cve": "CVE-2017-13081",
    "year": 2017,
    "domain": "Wi-Fi/车机联网",
    "vendor_product": "wpa_supplicant/802.11",
    "component": "802.11w IGTK",
    "type": "KRACK密钥重装",
    "summary": "802.11w IGTK密钥重装攻击。",
    "source_description": "Wi-Fi Protected Access (WPA and WPA2) that supports IEEE 802.11w allows reinstallation of the Integrity Group Temporal Key (IGTK) during the group key handshake, allowing an attacker within radio range to spoof frames from access points to clients.",
    "poc_status": "有公开PoC/研究代码",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-13081",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2017-13081",
        "http://www.securitytracker.com/id/1039581",
        "http://www.securityfocus.com/bid/101274",
        "http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html",
        "http://lists.opensuse.org/opensuse-security-announce/2017-10/msg00020.html",
        "http://www.debian.org/security/2017/dsa-3999",
        "http://www.securitytracker.com/id/1039578",
        "https://access.redhat.com/security/vulnerabilities/kracks",
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171016-wpa",
        "https://w1.fi/security/2017-1/wpa-packet-number-reuse-with-replayed-messages.txt",
        "http://www.arubanetworks.com/assets/alert/ARUBA-PSA-2017-007.txt",
        "https://cveawg.mitre.org/api/cve/CVE-2017-13081"
    ],
    "affected": [
        {
            "vendor": "Wi-Fi Alliance",
            "product": "Wi-Fi Protected Access (WPA and WPA2)",
            "versions": [
                {
                    "version": "WPA",
                    "status": "affected"
                }
,
                {
                    "version": "WPA2",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2017-13081",
        "wpa_supplicant",
        "IGTK",
        "KRACK",
        "Wi-Fi",
        "Protected",
        "Access",
        "WPA2",
        "supports",
        "IEEE",
        "reinstallation",
        "Integrity",
        "Group",
        "Temporal",
        "during",
        "group",
        "handshake",
        "allowing",
        "within",
        "radio",
        "range",
        "spoof",
        "frames",
        "access",
        "points",
        "clients",
        "Wi-Fi Alliance",
        "Wi-Fi Protected Access (WPA and WPA2"
    ]
}

# ── 硬件需求（HW_REQUIREMENTS） ────────────────────────────────────────
HW_REQUIREMENTS = {
    "hardware":   ['双频段 WiFi 适配器 ×2（AP + STA 角色）', '推荐：Alfa AWUS036ACH'],
    "connection": 'USB WiFi（wlan0 + wlan1）',
    "tools":      ['krackattacks-scripts（https://github.com/vanhoefm/krackattacks-scripts）', 'wpa_supplicant 2.6 实验版'],
    "firmware":   'N/A（针对 WPA2 握手层，驱动级注入）',
    "setup":      'sudo python3 krack-all-zero-tk.py wlan0 wlan1 <SSID> <client_mac>',
}



try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc59CVE201713081KRACKAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-074'
    meta_poc_name = 'CVE-2017-13081 KRACK密钥重装 Active Validation'
    meta_cve_id = 'CVE-2017-13081'
    meta_severity = 'High'
    meta_protocol = 'can'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['rf']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2017-13081'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2017-13081']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "59_WiFi_KRACK_IGTK_Key_Reinstall_Audit") if "VULN" in dir() else "59_WiFi_KRACK_IGTK_Key_Reinstall_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc59CVE201713081KRACKAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

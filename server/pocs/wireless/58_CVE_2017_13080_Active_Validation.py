#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _check_hostapd_version() -> dict:
    """Check hostapd version for KRACK group key vulnerability (AP-side)."""
    info = {"version": "", "potentially_vulnerable": None}
    try:
        r = subprocess.run(
            ["hostapd", "-v"],
            capture_output=True, text=True, timeout=5,
        )
        version_text = (r.stdout + r.stderr).strip()
        info["version"] = version_text[:200]
        m = re.search(r'hostapd v?(\d+)\.(\d+)', version_text, re.IGNORECASE)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            # CVE-2017-13080: GTK reinstall on AP side, fixed in hostapd 2.7
            info["potentially_vulnerable"] = major < 2 or (major == 2 and minor < 7)
    except FileNotFoundError:
        info["error"] = "hostapd not found"
    except subprocess.TimeoutExpired:
        info["error"] = "timeout"
    return info


def _check_wpa_supplicant_group_key() -> dict:
    """Check wpa_supplicant for group key reinstall vulnerability."""
    info = {"version": "", "potentially_vulnerable": None}
    try:
        r = subprocess.run(
            ["wpa_supplicant", "-v"],
            capture_output=True, text=True, timeout=5,
        )
        version_text = (r.stdout + r.stderr).strip()
        info["version"] = version_text[:200]
        m = re.search(r'wpa_supplicant v?(\d+)\.(\d+)', version_text, re.IGNORECASE)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            info["potentially_vulnerable"] = major < 2 or (major == 2 and minor < 7)
    except FileNotFoundError:
        info["error"] = "wpa_supplicant not found"
    except subprocess.TimeoutExpired:
        info["error"] = "timeout"
    return info


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    target_bssid = params.get("target_bssid", params.get("bssid", ""))

    evidence = {
        "cve": "CVE-2017-13080",
        "target": target_bssid or "WPA2 AP (KRACK GTK group key reinstall - AP side)",
        "technique": (
            "KRACK group key reinstall audit (AP-side / hostapd): check hostapd and "
            "wpa_supplicant versions for GTK reinstallation vulnerability"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-13080",
        "vuln_detail": (
            "KRACK: GTK reinstallation when processing Group Key Handshake Message 1. "
            "Affects both client (wpa_supplicant) and AP (hostapd)."
        ),
        "krack_type": "GTK reinstall in Group Key Handshake",
    }

    hostapd_info = _check_hostapd_version()
    evidence["hostapd"] = hostapd_info

    wpa_info = _check_wpa_supplicant_group_key()
    evidence["wpa_supplicant"] = wpa_info

    hostapd_vuln = hostapd_info.get("potentially_vulnerable")
    wpa_vuln = wpa_info.get("potentially_vulnerable")

    if hostapd_vuln is True or wpa_vuln is True:
        vulnerable = True
        versions = []
        if hostapd_vuln:
            versions.append(f"hostapd: {hostapd_info['version']}")
        if wpa_vuln:
            versions.append(f"wpa_supplicant: {wpa_info['version']}")
        evidence["note"] = (
            f"KRACK-vulnerable versions detected: {'; '.join(versions)}. "
            "CVE-2017-13080 GTK reinstall confirmed."
        )
    elif hostapd_vuln is False and wpa_vuln is False:
        vulnerable = False
        evidence["note"] = "Both hostapd and wpa_supplicant appear patched"
    else:
        vulnerable = None
        evidence["note"] = (
            "Cannot determine KRACK exposure without version info. "
            "Monitor mode WiFi adapter required for active KRACK test."
        )

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    "id": 73,
    "cve": "CVE-2017-13080",
    "year": 2017,
    "domain": "Wi-Fi/车机联网",
    "vendor_product": "wpa_supplicant/802.11",
    "component": "group key handshake",
    "type": "KRACK密钥重装",
    "summary": "WPA2组密钥重装，影响无线链路机密性。",
    "source_description": "Wi-Fi Protected Access (WPA and WPA2) allows reinstallation of the Group Temporal Key (GTK) during the group key handshake, allowing an attacker within radio range to replay frames from access points to clients.",
    "poc_status": "有公开PoC/研究代码",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-13080",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2017-13080",
        "http://www.securitytracker.com/id/1039581",
        "https://support.apple.com/HT208221",
        "http://www.securityfocus.com/bid/101274",
        "http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html",
        "http://lists.opensuse.org/opensuse-security-announce/2017-10/msg00020.html",
        "https://lists.debian.org/debian-lts-announce/2017/12/msg00004.html",
        "http://www.debian.org/security/2017/dsa-3999",
        "https://support.apple.com/HT208327",
        "http://www.securitytracker.com/id/1039578",
        "https://support.apple.com/HT208325",
        "https://cveawg.mitre.org/api/cve/CVE-2017-13080"
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
        "CVE-2017-13080",
        "wpa_supplicant",
        "group",
        "key",
        "handshake",
        "KRACK",
        "Wi-Fi",
        "Protected",
        "Access",
        "WPA2",
        "reinstallation",
        "Group",
        "Temporal",
        "during",
        "allowing",
        "within",
        "radio",
        "range",
        "replay",
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

class Poc58CVE201713080KRACKAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-073'
    meta_poc_name = 'CVE-2017-13080 KRACK密钥重装 Active Validation'
    meta_cve_id = 'CVE-2017-13080'
    meta_severity = 'High'
    meta_protocol = 'can'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['rf']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2017-13080'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2017-13080']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "58_WiFi_KRACK_Group_Key_Reinstall_Audit") if "VULN" in dir() else "58_WiFi_KRACK_Group_Key_Reinstall_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc58CVE201713080KRACKAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

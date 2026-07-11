#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _check_wpa_supplicant_version() -> dict:
    """Check wpa_supplicant version for KRACK vulnerability."""
    info = {"version": "", "potentially_vulnerable": None, "tool_found": False}
    for tool in ("wpa_supplicant", "wpa_supplicant.conf"):
        try:
            r = subprocess.run(
                ["wpa_supplicant", "-v"],
                capture_output=True, text=True, timeout=5,
            )
            info["tool_found"] = True
            version_text = (r.stdout + r.stderr).strip()
            info["version"] = version_text[:200]
            # KRACK fixed in wpa_supplicant 2.7
            m = re.search(r'wpa_supplicant v?(\d+)\.(\d+)', version_text, re.IGNORECASE)
            if m:
                major, minor = int(m.group(1)), int(m.group(2))
                if major < 2 or (major == 2 and minor < 7):
                    info["potentially_vulnerable"] = True
                else:
                    info["potentially_vulnerable"] = False
            break
        except FileNotFoundError:
            info["error"] = "wpa_supplicant not found"
        except subprocess.TimeoutExpired:
            info["error"] = "timeout"
    return info


def _check_monitor_mode_capable() -> dict:
    """Check if wireless adapter supports monitor mode."""
    info = {"monitor_capable": False, "interfaces": [], "iw_available": False}
    try:
        r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
        info["iw_available"] = True
        interfaces = re.findall(r'Interface\s+(\S+)', r.stdout)
        info["interfaces"] = interfaces
        # Check for monitor mode
        if interfaces:
            try:
                r2 = subprocess.run(
                    ["iw", "phy", "phy0", "info"],
                    capture_output=True, text=True, timeout=5,
                )
                if "monitor" in r2.stdout.lower():
                    info["monitor_capable"] = True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
    except FileNotFoundError:
        info["error"] = "iw not found"
    except subprocess.TimeoutExpired:
        info["error"] = "timeout"
    return info


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    target_bssid = params.get("target_bssid", params.get("bssid", ""))
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", ""))

    evidence = {
        "cve": "CVE-2017-13078",
        "target": target_bssid or target_ip or "WPA2 AP (KRACK group key reinstall)",
        "technique": (
            "KRACK group key reinstall audit: check wpa_supplicant version, "
            "verify monitor mode capability, check for Group Key Handshake vulnerability"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-13078",
        "vuln_detail": (
            "KRACK: Reinstallation of the group key (GTK) in the 4-way handshake. "
            "Attacker on same Wi-Fi network can decrypt/replay group-addressed frames."
        ),
        "krack_type": "GTK reinstall in 4-way handshake",
    }

    wpa_info = _check_wpa_supplicant_version()
    evidence["wpa_supplicant"] = wpa_info

    monitor_info = _check_monitor_mode_capable()
    evidence["wifi_adapter"] = monitor_info

    if wpa_info["potentially_vulnerable"] is True:
        vulnerable = True
        evidence["note"] = (
            f"wpa_supplicant {wpa_info['version']} is in KRACK-vulnerable range (< 2.7). "
            "CVE-2017-13078 group key reinstallation is exploitable."
        )
    elif wpa_info["potentially_vulnerable"] is False:
        vulnerable = False
        evidence["note"] = f"wpa_supplicant {wpa_info['version']} appears patched (>= 2.7)"
    else:
        vulnerable = None
        evidence["note"] = (
            "Cannot determine wpa_supplicant version automatically. "
            "KRACK requires monitor mode Wi-Fi adapter and target within radio range. "
            "Use krackattacks-poc-zerokey test tool for definitive assessment."
        )

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    "id": 71,
    "cve": "CVE-2017-13078",
    "year": 2017,
    "domain": "Wi-Fi/车机联网",
    "vendor_product": "wpa_supplicant/802.11",
    "component": "group key handshake",
    "type": "KRACK密钥重装",
    "summary": "WPA2组密钥握手重装攻击。",
    "source_description": "Wi-Fi Protected Access (WPA and WPA2) allows reinstallation of the Group Temporal Key (GTK) during the four-way handshake, allowing an attacker within radio range to replay frames from access points to clients.",
    "poc_status": "有公开PoC/研究代码",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-13078",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2017-13078",
        "http://www.securitytracker.com/id/1039581",
        "https://support.apple.com/HT208221",
        "http://www.securityfocus.com/bid/101274",
        "http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html",
        "http://lists.opensuse.org/opensuse-security-announce/2017-10/msg00020.html",
        "http://www.debian.org/security/2017/dsa-3999",
        "http://www.securitytracker.com/id/1039578",
        "https://access.redhat.com/security/vulnerabilities/kracks",
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171016-wpa",
        "https://access.redhat.com/errata/RHSA-2017:2911",
        "https://cveawg.mitre.org/api/cve/CVE-2017-13078"
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
        "CVE-2017-13078",
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
        "four-way",
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

class Poc56CVE201713078KRACKAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-056"
    meta_poc_name = 'CVE-2017-13078 KRACK密钥重装 Active Validation'
    meta_cve_id = 'CVE-2017-13078'
    meta_severity = 'High'
    meta_protocol = 'can'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['rf']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2017-13078'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2017-13078']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "56_WiFi_KRACK_Group_Key_Reinstall_Audit") if "VULN" in dir() else "56_WiFi_KRACK_Group_Key_Reinstall_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc56CVE201713078KRACKAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

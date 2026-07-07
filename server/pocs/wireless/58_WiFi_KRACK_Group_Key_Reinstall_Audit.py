#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


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
                },
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


class Poc58CVE201713080KRACKAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-073'
    meta_poc_name = 'CVE-2017-13080 KRACK密钥重装 Exposure Audit'
    meta_cve_id = 'CVE-2017-13080'
    meta_severity = 'High'
    meta_protocol = 'can'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['rf']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2017-13080'
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

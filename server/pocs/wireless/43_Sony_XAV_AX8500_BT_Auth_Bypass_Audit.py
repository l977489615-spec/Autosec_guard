#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 23,
    "cve": "CVE-2025-5476",
    "year": 2025,
    "domain": "蓝牙/IVI",
    "vendor_product": "Sony XAV-AX8500",
    "component": "Bluetooth stack",
    "type": "Bluetooth认证绕过",
    "summary": "Bluetooth隔离不当导致网络邻近攻击者绕过认证。",
    "source_description": "Sony XAV-AX8500 Bluetooth Improper Isolation Authentication Bypass Vulnerability. This vulnerability allows network-adjacent attackers to bypass authentication on affected Sony XAV-AX8500 devices. Authentication is not required to exploit this vulnerability.\n\nThe specific flaw exists within the implementation of ACL-U links. The issue results from the lack of L2CAP channel isolation. An attacker can leverage this vulnerability to bypass authentication on the system. Was ZDI-CAN-26284.",
    "poc_status": "有ZDI公开技术公告；未见官方PoC代码",
    "research_value": "非常适合IVI蓝牙协议栈模糊测试与攻击链研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-5476",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-5476",
        "https://www.zerodayinitiative.com/advisories/ZDI-25-357/",
        "https://www.sony.com/electronics/support/mobile-cd-players-digital-media-players-xav-series/xav-ax8500/software/00344092",
        "https://cveawg.mitre.org/api/cve/CVE-2025-5476"
    ],
    "affected": [
        {
            "vendor": "Sony",
            "product": "XAV-AX8500",
            "versions": [
                {
                    "version": "2.00.01",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-5476",
        "Sony",
        "XAV-AX8500",
        "Bluetooth",
        "stack",
        "Improper",
        "Isolation",
        "Authentication",
        "Bypass",
        "Vulnerability",
        "vulnerability",
        "network-adjacent",
        "attackers",
        "bypass",
        "authentication",
        "devices",
        "required",
        "exploit",
        "specific",
        "flaw",
        "exists",
        "within",
        "implementation",
        "ACL-U"
    ]
}


class Poc43CVE20255476AuthBypassAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-023'
    meta_poc_name = 'CVE-2025-5476 Bluetooth认证绕过 Exposure Audit'
    meta_cve_id = 'CVE-2025-5476'
    meta_severity = 'High'
    meta_protocol = 'bluetooth'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-5476'
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 25,
    "cve": "CVE-2025-5478",
    "year": 2025,
    "domain": "蓝牙/IVI",
    "vendor_product": "Sony XAV-AX8500",
    "component": "Bluetooth stack",
    "type": "Bluetooth SDP整数溢出/RCE",
    "summary": "SDP协议实现整数溢出，无需认证即可触发RCE。",
    "source_description": "Sony XAV-AX8500 Bluetooth SDP Protocol Integer Overflow Remote Code Execution Vulnerability. This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of Sony XAV-AX8500 devices. Authentication is not required to exploit this vulnerability.\n\nThe specific flaw exists within the implementation of the Bluetooth SDP protocol. The issue results from the lack of proper validation of user-supplied data, which can result in an integer overflow before allocating a buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-26288.",
    "poc_status": "有ZDI公开技术公告；未见官方PoC代码",
    "research_value": "非常适合IVI蓝牙协议栈模糊测试与攻击链研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-5478",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-5478",
        "https://www.zerodayinitiative.com/advisories/ZDI-25-355/",
        "https://www.sony.com/electronics/support/mobile-cd-players-digital-media-players-xav-series/xav-ax8500/software/00344092",
        "https://cveawg.mitre.org/api/cve/CVE-2025-5478"
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
        "CVE-2025-5478",
        "Sony",
        "XAV-AX8500",
        "Bluetooth",
        "stack",
        "SDP",
        "RCE",
        "Protocol",
        "Integer",
        "Overflow",
        "Remote",
        "Code",
        "Execution",
        "Vulnerability",
        "vulnerability",
        "network-adjacent",
        "attackers",
        "execute",
        "arbitrary",
        "code",
        "installations",
        "devices",
        "Authentication",
        "required",
        "exploit",
        "specific",
        "flaw"
    ]
}


class Poc45CVE20255478RCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-025'
    meta_poc_name = 'CVE-2025-5478 Bluetooth SDP整数溢出/RCE Exposure Audit'
    meta_cve_id = 'CVE-2025-5478'
    meta_severity = 'High'
    meta_protocol = 'bluetooth'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-5478'
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

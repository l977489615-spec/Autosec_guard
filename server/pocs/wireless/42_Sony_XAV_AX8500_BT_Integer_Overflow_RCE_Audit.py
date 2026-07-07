#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 22,
    "cve": "CVE-2025-5475",
    "year": 2025,
    "domain": "蓝牙/IVI",
    "vendor_product": "Sony XAV-AX8500",
    "component": "Bluetooth stack",
    "type": "Bluetooth整数溢出/RCE",
    "summary": "Bluetooth包处理整数溢出，配对恶意设备后可RCE。",
    "source_description": "Sony XAV-AX8500 Bluetooth Packet Handling Integer Overflow Remote Code Execution Vulnerability. This vulnerability allows network-adjacent attackers to execute arbitrary code on affected Sony XAV-AX8500 devices. An attacker must first obtain the ability to pair a malicious Bluetooth device with the target system in order to exploit this vulnerability.\n\nThe specific flaw exists within the handling of Bluetooth packets. The issue results from the lack of proper validation of user-supplied data, which can result in an integer overflow before writing to memory. An attacker can leverage this vulnerability to execute code in the context of the elysian-bt-service process. Was ZDI-CAN-26283.",
    "poc_status": "有ZDI公开技术公告；未见官方PoC代码",
    "research_value": "非常适合IVI蓝牙协议栈模糊测试与攻击链研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-5475",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-5475",
        "https://www.zerodayinitiative.com/advisories/ZDI-25-353/",
        "https://www.sony.com/electronics/support/mobile-cd-players-digital-media-players-xav-series/xav-ax8500/software/00344092",
        "https://cveawg.mitre.org/api/cve/CVE-2025-5475"
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
        "CVE-2025-5475",
        "Sony",
        "XAV-AX8500",
        "Bluetooth",
        "stack",
        "RCE",
        "Packet",
        "Handling",
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
        "devices",
        "must",
        "first",
        "obtain",
        "ability",
        "pair",
        "malicious"
    ]
}


class Poc42CVE20255475RCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-022'
    meta_poc_name = 'CVE-2025-5475 Bluetooth整数溢出/RCE Exposure Audit'
    meta_cve_id = 'CVE-2025-5475'
    meta_severity = 'High'
    meta_protocol = 'bluetooth'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-5475'
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

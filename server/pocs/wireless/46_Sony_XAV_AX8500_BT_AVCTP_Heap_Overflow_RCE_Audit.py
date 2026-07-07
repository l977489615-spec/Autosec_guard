#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 26,
    "cve": "CVE-2025-5479",
    "year": 2025,
    "domain": "蓝牙/IVI",
    "vendor_product": "Sony XAV-AX8500",
    "component": "Bluetooth stack",
    "type": "Bluetooth AVCTP堆溢出/RCE",
    "summary": "AVCTP协议实现堆缓冲区溢出，配对恶意设备后可RCE。",
    "source_description": "Sony XAV-AX8500 Bluetooth AVCTP Protocol Heap-based Buffer Overflow Remote Code Execution Vulnerability. This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of Sony XAV-AX8500 devices. An attacker must first obtain the ability to pair a malicious Bluetooth device with the target system in order to exploit this vulnerability.\n\nThe specific flaw exists within the implementation of the Bluetooth AVCTP protocol. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a heap-based buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26290.",
    "poc_status": "有ZDI公开技术公告；未见官方PoC代码",
    "research_value": "非常适合IVI蓝牙协议栈模糊测试与攻击链研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-5479",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-5479",
        "https://www.zerodayinitiative.com/advisories/ZDI-25-356/",
        "https://www.sony.com/electronics/support/mobile-cd-players-digital-media-players-xav-series/xav-ax8500/software/00344092",
        "https://cveawg.mitre.org/api/cve/CVE-2025-5479"
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
        "CVE-2025-5479",
        "Sony",
        "XAV-AX8500",
        "Bluetooth",
        "stack",
        "AVCTP",
        "RCE",
        "Protocol",
        "Heap-based",
        "Buffer",
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
        "must",
        "first",
        "obtain",
        "ability"
    ]
}


class Poc46CVE20255479RCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-026'
    meta_poc_name = 'CVE-2025-5479 Bluetooth AVCTP堆溢出/RCE Exposure Audit'
    meta_cve_id = 'CVE-2025-5479'
    meta_severity = 'High'
    meta_protocol = 'bluetooth'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-5479'
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

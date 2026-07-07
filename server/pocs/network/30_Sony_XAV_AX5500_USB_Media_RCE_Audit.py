#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 36,
    "cve": "CVE-2024-23935",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Sony XAV-AX5500",
    "component": "媒体解析/USB",
    "type": "内存破坏/RCE",
    "summary": "车机媒体/USB输入处理存在内存破坏型RCE。",
    "source_description": "Alpine Halo9 DecodeUTF7 Stack-based Buffer Overflow Remote Code Execution Vulnerability. This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of Alpine Halo9 devices. An attacker must first obtain the ability to pair a malicious Bluetooth device with the target system in order to exploit this vulnerability.\n\nThe specific flaw exists within the DecodeUTF7 function. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of root.\n\nWas ZDI-CAN-23249",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23935",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23935",
        "https://www.zerodayinitiative.com/advisories/ZDI-24-848/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-23935"
    ],
    "affected": [
        {
            "vendor": "Alpine",
            "product": "Halo9",
            "versions": [
                {
                    "version": "6.0.000",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-23935",
        "Sony",
        "XAV-AX5500",
        "USB",
        "RCE",
        "Alpine",
        "Halo9",
        "DecodeUTF7",
        "Stack-based",
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
        "ability",
        "pair",
        "malicious"
    ]
}


class Poc30CVE202423935RCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-036'
    meta_poc_name = 'CVE-2024-23935 内存破坏/RCE Exposure Audit'
    meta_cve_id = 'CVE-2024-23935'
    meta_severity = 'High'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-23935'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

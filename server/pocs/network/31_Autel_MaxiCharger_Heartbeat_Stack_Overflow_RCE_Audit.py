#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 37,
    "cve": "CVE-2024-23957",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Autel MaxiCharger AC Elite Business C50",
    "component": "DLB_HostHeartBeat",
    "type": "栈溢出/RCE",
    "summary": "网络邻近攻击者无需认证可通过心跳处理触发RCE。",
    "source_description": "Autel MaxiCharger AC Elite Business C50 DLB_HostHeartBeat Stack-based Buffer Overflow Remote Code Execution Vulnerability. This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of Autel MaxiCharger AC Elite Business C50 charging stations. Authentication is not required to exploit this vulnerability.\n\nThe specific flaw exists within the DLB_HostHeartBeat handler of the DLB protocol implementation. When parsing an AES key, the process does not properly validate the length of user-supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of the device.\n\nWas ZDI-CAN-23241",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23957",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23957",
        "https://www.zerodayinitiative.com/advisories/ZDI-24-854/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-23957"
    ],
    "affected": [
        {
            "vendor": "Autel",
            "product": "MaxiCharger AC Elite Business C50",
            "versions": [
                {
                    "version": "1.32.00",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-23957",
        "Autel",
        "MaxiCharger",
        "Elite",
        "Business",
        "C50",
        "DLB_HostHeartBeat",
        "RCE",
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
        "charging",
        "stations",
        "Authentication",
        "required",
        "MaxiCharger AC Elite Business C50"
    ]
}


class Poc31CVE202423957StackOverflowRCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-037'
    meta_poc_name = 'CVE-2024-23957 栈溢出/RCE Exposure Audit'
    meta_cve_id = 'CVE-2024-23957'
    meta_severity = 'High'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-23957'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

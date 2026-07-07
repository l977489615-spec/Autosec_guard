#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 39,
    "cve": "CVE-2024-23967",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Alpine Halo9",
    "component": "车机服务/固件",
    "type": "输入校验或内存破坏",
    "summary": "Alpine Halo9 IVI攻击面相关缺陷，可用于本地/物理链式攻击。",
    "source_description": "Autel MaxiCharger AC Elite Business C50 WebSocket Base64 Decoding Stack-based Buffer Overflow Remote Code Execution Vulnerability. This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of Autel MaxiCharger AC Elite Business C50 chargers. Although authentication is required to exploit this vulnerability, the existing authentication mechanism can be bypassed.\n\nThe specific flaw exists within the handling of base64-encoded data within WebSocket messages. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of the device.\n\nWas ZDI-CAN-23230",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23967",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23967",
        "https://www.zerodayinitiative.com/advisories/ZDI-24-853/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-23967"
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
        "CVE-2024-23967",
        "Alpine",
        "Halo9",
        "Autel",
        "MaxiCharger",
        "Elite",
        "Business",
        "WebSocket",
        "Base64",
        "Decoding",
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
        "chargers",
        "Although",
        "MaxiCharger AC Elite Business C50"
    ]
}


class Poc33CVE202423967InputValidationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-039'
    meta_poc_name = 'CVE-2024-23967 输入校验或内存破坏 Exposure Audit'
    meta_cve_id = 'CVE-2024-23967'
    meta_severity = 'High'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-23967'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

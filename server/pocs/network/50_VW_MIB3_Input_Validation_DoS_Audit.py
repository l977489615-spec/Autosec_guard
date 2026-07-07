#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 57,
    "cve": "CVE-2023-28911",
    "year": 2023,
    "domain": "IVI/云端/EVSE/OS",
    "vendor_product": "Volkswagen MIB3 Infotainment",
    "component": "MIB3 IVI",
    "type": "输入校验/DoS",
    "summary": "Skoda Superb III MIB3 IVI漏洞，影响多个OEM部件号。",
    "source_description": "A specific flaw exists within the Bluetooth stack of the MIB3 infotainment. The issue results from the lack of proper validation of user-supplied data, which can result in an arbitrary channel disconnection. An attacker can leverage this vulnerability to cause a denial-of-service attack for every connected client of the infotainment device.\nThe vulnerability was originally discovered in Skoda Superb III car with MIB3 infotainment unit OEM part number 3V0035820. The list of affected MIB3 OEM part numbers is provided in the referenced resources.",
    "poc_status": "公开公告；大多未见一步式PoC",
    "research_value": "作为近两年前后演进基线，对比2024-2026风险变化。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-28911",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-28911",
        "https://i.blackhat.com/EU-24/Presentations/EU-24-Parnishchev-OverTheAirVW.pdf",
        "https://pcacybersecurity.com/resources/advisory/vulnerabilities-in-vw-mib3-infotainment-2",
        "https://asrg.io/security-advisories/vulnerabilities-in-volkswagen-mib3-infotainment-part-2/",
        "https://cveawg.mitre.org/api/cve/CVE-2023-28911"
    ],
    "affected": [
        {
            "vendor": "Preh Car Connect GmbH (JOYNEXT GmbH)",
            "product": "Volkswagen MIB3 infotainment system MIB3 OI MQB",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThanOrEqual": "0304",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2023-28911",
        "Volkswagen",
        "MIB3",
        "Infotainment",
        "IVI",
        "DoS",
        "specific",
        "flaw",
        "exists",
        "within",
        "Bluetooth",
        "stack",
        "infotainment",
        "issue",
        "results",
        "lack",
        "proper",
        "validation",
        "user-supplied",
        "data",
        "which",
        "result",
        "arbitrary",
        "channel",
        "disconnection",
        "leverage",
        "vulnerability",
        "cause",
        "denial-of-service",
        "attack"
    ]
}


class Poc50CVE202328911DoSInputValidationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-057'
    meta_poc_name = 'CVE-2023-28911 输入校验/DoS Exposure Audit'
    meta_cve_id = 'CVE-2023-28911'
    meta_severity = 'Medium'
    meta_protocol = 'https'
    meta_target_os = ['linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-28911'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 56,
    "cve": "CVE-2023-28910",
    "year": 2023,
    "domain": "IVI/云端/EVSE/OS",
    "vendor_product": "Volkswagen MIB3 Infotainment",
    "component": "MIB3 IVI update/service",
    "type": "访问控制/认证缺陷",
    "summary": "MIB3 IVI漏洞，可与其他缺陷组成攻击链。",
    "source_description": "A specific flaw exists within the Bluetooth stack of the MIB3 infotainment system. The issue results from the disabled abortion flag eventually leading to bypassing assertion functions.\nThe vulnerability was originally discovered in Skoda Superb III car with MIB3 infotainment unit OEM part number 3V0035820. The list of affected MIB3 OEM part numbers is provided in the referenced resources.",
    "poc_status": "公开公告；大多未见一步式PoC",
    "research_value": "作为近两年前后演进基线，对比2024-2026风险变化。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-28910",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-28910",
        "https://i.blackhat.com/EU-24/Presentations/EU-24-Parnishchev-OverTheAirVW.pdf",
        "https://pcacybersecurity.com/resources/advisory/vulnerabilities-in-vw-mib3-infotainment-2",
        "https://asrg.io/security-advisories/vulnerabilities-in-volkswagen-mib3-infotainment-part-2/",
        "https://cveawg.mitre.org/api/cve/CVE-2023-28910"
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
        "CVE-2023-28910",
        "Volkswagen",
        "MIB3",
        "Infotainment",
        "IVI",
        "update",
        "service",
        "specific",
        "flaw",
        "exists",
        "within",
        "Bluetooth",
        "stack",
        "infotainment",
        "system",
        "issue",
        "results",
        "disabled",
        "abortion",
        "flag",
        "eventually",
        "leading",
        "bypassing",
        "assertion",
        "functions",
        "vulnerability",
        "originally",
        "discovered",
        "Skoda",
        "Superb"
    ]
}


class Poc49CVE202328910AccessControlAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-056'
    meta_poc_name = 'CVE-2023-28910 访问控制/认证缺陷 Exposure Audit'
    meta_cve_id = 'CVE-2023-28910'
    meta_severity = 'Medium'
    meta_protocol = 'https'
    meta_target_os = ['linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-28910'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

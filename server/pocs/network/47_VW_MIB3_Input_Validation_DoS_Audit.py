#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 54,
    "cve": "CVE-2023-28903",
    "year": 2023,
    "domain": "IVI/云端/EVSE/OS",
    "vendor_product": "Volkswagen MIB3 Infotainment",
    "component": "MIB3 IVI",
    "type": "输入校验/DoS",
    "summary": "VW MIB3 IVI相关漏洞，影响Skoda Superb III等车型。",
    "source_description": "An integer overflow in the image processing binary of the MIB3 infotainment unit allows an attacker with local access to the vehicle to cause a denial-of-service of the infotainment system.",
    "poc_status": "公开公告；大多未见一步式PoC",
    "research_value": "作为近两年前后演进基线，对比2024-2026风险变化。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-28903",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-28903",
        "https://i.blackhat.com/EU-24/Presentations/EU-24-Parnishchev-OverTheAirVW.pdf",
        "https://pcacybersecurity.com/resources/advisory/vulnerabilities-in-vw-mib3-infotainment-2",
        "https://asrg.io/security-advisories/vulnerabilities-in-volkswagen-mib3-infotainment-part-2/",
        "https://cveawg.mitre.org/api/cve/CVE-2023-28903"
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
        "CVE-2023-28903",
        "Volkswagen",
        "MIB3",
        "Infotainment",
        "IVI",
        "DoS",
        "integer",
        "overflow",
        "image",
        "processing",
        "binary",
        "infotainment",
        "unit",
        "local",
        "access",
        "cause",
        "denial-of-service",
        "system",
        "Preh Car Connect GmbH (JOYNEXT GmbH",
        "Volkswagen MIB3 infotainment system MIB3 OI MQB"
    ]
}


class Poc47CVE202328903DoSInputValidationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-054'
    meta_poc_name = 'CVE-2023-28903 输入校验/DoS Exposure Audit'
    meta_cve_id = 'CVE-2023-28903'
    meta_severity = 'Medium'
    meta_protocol = 'https'
    meta_target_os = ['linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-28903'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

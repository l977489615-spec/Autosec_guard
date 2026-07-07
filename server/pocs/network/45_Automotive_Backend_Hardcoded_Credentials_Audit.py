#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 52,
    "cve": "CVE-2023-28895",
    "year": 2023,
    "domain": "IVI/云端/EVSE/OS",
    "vendor_product": "Automotive backend/Skoda/VW ecosystem",
    "component": "credentials",
    "type": "硬编码凭据",
    "summary": "车联网服务/组件存在硬编码凭据风险。",
    "source_description": "The password for access to the debugging console of the PoWer Controller chip (PWC) of the MIB3 infotainment is hard-coded in the firmware. The console allows attackers with physical access to the MIB3 unit to gain full control over the PWC chip.\n\nVulnerability found on Škoda Superb III (3V3) - 2.0 TDI manufactured in 2022.",
    "poc_status": "公开公告；大多未见一步式PoC",
    "research_value": "作为近两年前后演进基线，对比2024-2026风险变化。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-28895",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-28895",
        "https://asrg.io/security-advisories/hard-coded-password-for-access-to-power-controller-chip-memory/",
        "https://cveawg.mitre.org/api/cve/CVE-2023-28895"
    ],
    "affected": [
        {
            "vendor": "JOYNEXT",
            "product": "MIB3 Infotainment Unit",
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
        "CVE-2023-28895",
        "Automotive",
        "backend",
        "Skoda",
        "ecosystem",
        "credentials",
        "password",
        "access",
        "debugging",
        "console",
        "PoWer",
        "Controller",
        "chip",
        "MIB3",
        "infotainment",
        "hard-coded",
        "firmware",
        "attackers",
        "physical",
        "unit",
        "gain",
        "full",
        "control",
        "over",
        "Vulnerability",
        "found",
        "koda",
        "Superb",
        "manufactured",
        "JOYNEXT"
    ]
}


class Poc45CVE202328895ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-052'
    meta_poc_name = 'CVE-2023-28895 硬编码凭据 Exposure Audit'
    meta_cve_id = 'CVE-2023-28895'
    meta_severity = 'High'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-28895'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

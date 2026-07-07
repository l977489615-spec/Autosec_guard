#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 59,
    "cve": "CVE-2023-29126",
    "year": 2023,
    "domain": "IVI/云端/EVSE/OS",
    "vendor_product": "Enel X Waybox EV charger",
    "component": "PHP web management",
    "type": "PHP类型混淆/认证绕过",
    "summary": "PHP类型混淆可在特定条件下绕过认证。",
    "source_description": "The Waybox Enel X web management application contains a PHP-type juggling vulnerability that may allow a brute force process and under certain conditions bypass authentication.",
    "poc_status": "公开公告；大多未见一步式PoC",
    "research_value": "作为近两年前后演进基线，对比2024-2026风险变化。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-29126",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-29126",
        "https://support-emobility.enelx.com/content/dam/enelxmobility/italia/documenti/manuali-schede-tecniche/Waybox-3-Security-Bulletin-06-2024-V1.pdf",
        "https://cveawg.mitre.org/api/cve/CVE-2023-29126"
    ],
    "affected": [
        {
            "vendor": "Enel X",
            "product": "JuiceBox Pro 3.0 22kW Cellular",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThanOrEqual": "2.1.1.0_JB3VU096A",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2023-29126",
        "Enel",
        "Waybox",
        "charger",
        "PHP",
        "web",
        "management",
        "application",
        "contains",
        "PHP-type",
        "juggling",
        "vulnerability",
        "allow",
        "brute",
        "force",
        "process",
        "under",
        "certain",
        "conditions",
        "bypass",
        "authentication",
        "Enel X",
        "JuiceBox Pro 3.0 22kW Cellular"
    ]
}


class Poc51CVE202329126AuthBypassAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-059'
    meta_poc_name = 'CVE-2023-29126 PHP类型混淆/认证绕过 Exposure Audit'
    meta_cve_id = 'CVE-2023-29126'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-29126'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

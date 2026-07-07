#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 85,
    "cve": "CVE-2025-24132",
    "year": 2025,
    "domain": "车载互联/CarPlay相关",
    "vendor_product": "Apple AirPlay/CarPlay ecosystem",
    "component": "AirPlay SDK",
    "type": "AirBorne系列漏洞",
    "summary": "AirPlay协议/SDK漏洞，影响部分第三方设备与车载集成生态。",
    "source_description": "The issue was addressed with improved memory handling. This issue is fixed in AirPlay audio SDK 2.7.1 and AirPlay video SDK 3.6.0.126. An attacker on the local network may cause an unexpected app termination.",
    "poc_status": "有Oligo公开研究；PoC有限",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-24132",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-24132",
        "https://support.apple.com/en-us/122403",
        "https://cveawg.mitre.org/api/cve/CVE-2025-24132"
    ],
    "affected": [
        {
            "vendor": "Apple",
            "product": "AirPlay audio SDK",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "2.7.1",
                    "versionType": "custom"
                }
            ]
        },
        {
            "vendor": "Apple",
            "product": "AirPlay video SDK",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "2.7.1",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-24132",
        "Apple",
        "AirPlay",
        "CarPlay",
        "ecosystem",
        "SDK",
        "AirBorne",
        "issue",
        "addressed",
        "improved",
        "memory",
        "handling",
        "fixed",
        "audio",
        "video",
        "local",
        "network",
        "cause",
        "unexpected",
        "termination",
        "AirPlay audio SDK",
        "AirPlay video SDK"
    ]
}


class Poc61CVE202524132AirBorneAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-085'
    meta_poc_name = 'CVE-2025-24132 AirBorne系列漏洞 Exposure Audit'
    meta_cve_id = 'CVE-2025-24132'
    meta_severity = 'High'
    meta_protocol = 'carplay'
    meta_target_os = ['all']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['application']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-24132'
    meta_attack_surface = '车机APP/应用'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 82,
    "cve": "CVE-2024-23204",
    "year": 2024,
    "domain": "车载互联/CarPlay相关",
    "vendor_product": "Apple AirPlay/CarPlay ecosystem",
    "component": "AirPlay SDK",
    "type": "内存破坏/协议缺陷",
    "summary": "AirPlay/CarPlay生态相关协议漏洞之一，第三方车载设备可能受影响。",
    "source_description": "The issue was addressed with additional permissions checks. This issue is fixed in iOS 16.7.6 and iPadOS 16.7.6, iOS 17.3 and iPadOS 17.3, macOS Monterey 12.7.4, macOS Sonoma 14.3, macOS Ventura 13.6.5, watchOS 10.3. A shortcut may be able to use sensitive data with certain actions without prompting the user.",
    "poc_status": "有公开研究；PoC有限",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23204",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23204",
        "https://support.apple.com/en-us/120304",
        "https://support.apple.com/en-us/120306",
        "https://support.apple.com/en-us/120309",
        "https://support.apple.com/en-us/120880",
        "https://support.apple.com/en-us/120884",
        "https://support.apple.com/en-us/120886",
        "https://cveawg.mitre.org/api/cve/CVE-2024-23204"
    ],
    "affected": [
        {
            "vendor": "Apple",
            "product": "iOS and iPadOS",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "16.7.6",
                    "versionType": "custom"
                },
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "17.3",
                    "versionType": "custom"
                }
            ]
        },
        {
            "vendor": "Apple",
            "product": "macOS",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "12.7.4",
                    "versionType": "custom"
                },
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "13.6.5",
                    "versionType": "custom"
                },
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "14.3",
                    "versionType": "custom"
                }
            ]
        },
        {
            "vendor": "Apple",
            "product": "watchOS",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "10.3",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-23204",
        "Apple",
        "AirPlay",
        "CarPlay",
        "ecosystem",
        "SDK",
        "issue",
        "addressed",
        "additional",
        "permissions",
        "checks",
        "fixed",
        "iPadOS",
        "macOS",
        "Monterey",
        "Sonoma",
        "Ventura",
        "watchOS",
        "shortcut",
        "able",
        "sensitive",
        "data",
        "certain",
        "actions",
        "without",
        "prompting",
        "user",
        "iOS and iPadOS"
    ]
}


class Poc59CVE202423204ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-082'
    meta_poc_name = 'CVE-2024-23204 内存破坏/协议缺陷 Exposure Audit'
    meta_cve_id = 'CVE-2024-23204'
    meta_severity = 'High'
    meta_protocol = 'carplay'
    meta_target_os = ['all']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['application']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-23204'
    meta_attack_surface = '车机APP/应用'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

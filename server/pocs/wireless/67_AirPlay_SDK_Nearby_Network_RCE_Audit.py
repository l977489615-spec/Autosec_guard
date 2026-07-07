#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 84,
    "cve": "CVE-2024-23206",
    "year": 2024,
    "domain": "车载互联/CarPlay相关",
    "vendor_product": "Apple AirPlay/CarPlay ecosystem",
    "component": "AirPlay SDK",
    "type": "RCE/网络邻近攻击",
    "summary": "AirPlay第三方SDK相关漏洞，Wi-Fi邻近攻击面。",
    "source_description": "An access issue was addressed with improved access restrictions. This issue is fixed in Safari 17.3, iOS 16.7.5 and iPadOS 16.7.5, iOS 17.3 and iPadOS 17.3, macOS Sonoma 14.3, tvOS 17.3, watchOS 10.3. A maliciously crafted webpage may be able to fingerprint the user.",
    "poc_status": "有公开研究；PoC有限",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23206",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23206",
        "https://support.apple.com/en-us/120304",
        "https://support.apple.com/en-us/120306",
        "https://support.apple.com/en-us/120309",
        "https://support.apple.com/en-us/120310",
        "https://support.apple.com/en-us/120311",
        "https://support.apple.com/en-us/120339",
        "https://cveawg.mitre.org/api/cve/CVE-2024-23206"
    ],
    "affected": [
        {
            "vendor": "Apple",
            "product": "Safari",
            "versions": [
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
            "product": "iOS and iPadOS",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "16.7.5",
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
                    "lessThan": "14.3",
                    "versionType": "custom"
                }
            ]
        },
        {
            "vendor": "Apple",
            "product": "tvOS",
            "versions": [
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
        "CVE-2024-23206",
        "Apple",
        "AirPlay",
        "CarPlay",
        "ecosystem",
        "SDK",
        "RCE",
        "access",
        "issue",
        "addressed",
        "improved",
        "restrictions",
        "fixed",
        "Safari",
        "iPadOS",
        "macOS",
        "Sonoma",
        "tvOS",
        "watchOS",
        "maliciously",
        "crafted",
        "webpage",
        "able",
        "fingerprint",
        "user",
        "iOS and iPadOS"
    ]
}


class Poc67CVE202423206RCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-084'
    meta_poc_name = 'CVE-2024-23206 RCE/网络邻近攻击 Exposure Audit'
    meta_cve_id = 'CVE-2024-23206'
    meta_severity = 'High'
    meta_protocol = 'wifi'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['wifi']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-23206'
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

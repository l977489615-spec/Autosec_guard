#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 87,
    "cve": "CVE-2025-24271",
    "year": 2025,
    "domain": "车载互联/CarPlay相关",
    "vendor_product": "Apple AirPlay/CarPlay ecosystem",
    "component": "AirPlay SDK",
    "type": "AirBorne系列漏洞",
    "summary": "AirPlay/CarPlay集成设备潜在网络攻击面。",
    "source_description": "An access issue was addressed with improved access restrictions. This issue is fixed in iOS 18.4 and iPadOS 18.4, iPadOS 17.7.6, macOS Sequoia 15.4, macOS Sonoma 14.7.5, macOS Ventura 13.7.5, tvOS 18.4, visionOS 2.4. An unauthenticated user on the same network as a signed-in Mac could send it AirPlay commands without pairing.",
    "poc_status": "有Oligo公开研究；PoC有限",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-24271",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-24271",
        "https://support.apple.com/en-us/122371",
        "https://support.apple.com/en-us/122372",
        "https://support.apple.com/en-us/122373",
        "https://support.apple.com/en-us/122374",
        "https://support.apple.com/en-us/122375",
        "https://support.apple.com/en-us/122377",
        "https://support.apple.com/en-us/122378",
        "https://cveawg.mitre.org/api/cve/CVE-2025-24271"
    ],
    "affected": [
        {
            "vendor": "Apple",
            "product": "iOS and iPadOS",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "18.4",
                    "versionType": "custom"
                }
            ]
        },
        {
            "vendor": "Apple",
            "product": "iPadOS",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "17.7.6",
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
                    "lessThan": "13.7.5",
                    "versionType": "custom"
                },
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "14.7.5",
                    "versionType": "custom"
                },
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "15.4",
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
                    "lessThan": "18.4",
                    "versionType": "custom"
                }
            ]
        },
        {
            "vendor": "Apple",
            "product": "visionOS",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "2.4",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-24271",
        "Apple",
        "AirPlay",
        "CarPlay",
        "ecosystem",
        "SDK",
        "AirBorne",
        "access",
        "issue",
        "addressed",
        "improved",
        "restrictions",
        "fixed",
        "iPadOS",
        "macOS",
        "Sequoia",
        "Sonoma",
        "Ventura",
        "tvOS",
        "visionOS",
        "unauthenticated",
        "user",
        "same",
        "network",
        "signed-in",
        "could",
        "send",
        "commands",
        "without",
        "iOS and iPadOS"
    ]
}


class Poc63CVE202524271AirBorneAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-087'
    meta_poc_name = 'CVE-2025-24271 AirBorne系列漏洞 Exposure Audit'
    meta_cve_id = 'CVE-2025-24271'
    meta_severity = 'High'
    meta_protocol = 'carplay'
    meta_target_os = ['all']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['application']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-24271'
    meta_attack_surface = '车机APP/应用'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

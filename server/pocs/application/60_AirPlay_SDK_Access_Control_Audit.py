#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 83,
    "cve": "CVE-2024-23205",
    "year": 2024,
    "domain": "车载互联/CarPlay相关",
    "vendor_product": "Apple AirPlay/CarPlay ecosystem",
    "component": "AirPlay SDK",
    "type": "认证/访问控制缺陷",
    "summary": "AirPlay SDK相关漏洞，可能影响CarPlay/车载集成设备。",
    "source_description": "A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in iOS 17.4 and iPadOS 17.4, macOS Sonoma 14.4. An app may be able to access sensitive user data.",
    "poc_status": "有公开研究；PoC有限",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23205",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23205",
        "https://support.apple.com/en-us/120893",
        "https://support.apple.com/en-us/120895",
        "https://cveawg.mitre.org/api/cve/CVE-2024-23205"
    ],
    "affected": [
        {
            "vendor": "Apple",
            "product": "iOS and iPadOS",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "17.4",
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
                    "lessThan": "14.4",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-23205",
        "Apple",
        "AirPlay",
        "CarPlay",
        "ecosystem",
        "SDK",
        "privacy",
        "issue",
        "addressed",
        "improved",
        "private",
        "data",
        "redaction",
        "entries",
        "fixed",
        "iPadOS",
        "macOS",
        "Sonoma",
        "able",
        "access",
        "sensitive",
        "user",
        "iOS and iPadOS"
    ]
}


class Poc60CVE202423205AccessControlAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-083'
    meta_poc_name = 'CVE-2024-23205 认证/访问控制缺陷 Exposure Audit'
    meta_cve_id = 'CVE-2024-23205'
    meta_severity = 'High'
    meta_protocol = 'carplay'
    meta_target_os = ['all']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['application']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-23205'
    meta_attack_surface = '车机APP/应用'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

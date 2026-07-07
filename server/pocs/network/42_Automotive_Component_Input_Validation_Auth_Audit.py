#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 49,
    "cve": "CVE-2024-7746",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Automotive embedded component",
    "component": "车载软件组件",
    "type": "输入校验/认证缺陷",
    "summary": "ASRG披露的车载组件漏洞，需跟踪厂商修复。",
    "source_description": "Use of Default Credentials vulnerability in Tananaev Solutions Traccar Server on Administrator Panel modules allows Authentication Abuse.This issue affects the privileged transactions implemented by the Traccar solution that should otherwise be protected by the authentication mechanism. \nThese transactions could have an impact on any sensitive aspect of the platform, including Confidentiality, Integrity and Availability.",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-7746",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-7746",
        "https://asrg.io/security-advisories/cve-2024-7746/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-7746"
    ],
    "affected": [
        {
            "vendor": "Traccar",
            "product": "Server",
            "versions": [
                {
                    "version": "2.12",
                    "status": "unaffected",
                    "lessThanOrEqual": "6.2",
                    "versionType": "git"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-7746",
        "Automotive",
        "embedded",
        "component",
        "Default",
        "Credentials",
        "vulnerability",
        "Tananaev",
        "Solutions",
        "Traccar",
        "Server",
        "Administrator",
        "Panel",
        "modules",
        "Authentication",
        "Abuse.This",
        "issue",
        "affects",
        "privileged",
        "transactions",
        "implemented",
        "solution",
        "should",
        "otherwise",
        "protected",
        "authentication",
        "mechanism",
        "These",
        "could",
        "have"
    ]
}


class Poc42CVE20247746InputValidationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-049'
    meta_poc_name = 'CVE-2024-7746 输入校验/认证缺陷 Exposure Audit'
    meta_cve_id = 'CVE-2024-7746'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-7746'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

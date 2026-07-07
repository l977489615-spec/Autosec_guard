#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 53,
    "cve": "CVE-2023-28900",
    "year": 2023,
    "domain": "IVI/云端/EVSE/OS",
    "vendor_product": "Škoda Connect cloud",
    "component": "VIN-to-user backend API",
    "type": "越权/信息泄露",
    "summary": "通过任意VIN可获得Skoda Connect用户昵称与标识符。",
    "source_description": "The Skoda Automotive cloud contains a Broken Access Control vulnerability, allowing to obtain nicknames and other user identifiers of Skoda Connect service users by specifying an arbitrary vehicle VIN number.",
    "poc_status": "公开公告；大多未见一步式PoC",
    "research_value": "作为近两年前后演进基线，对比2024-2026风险变化。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-28900",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-28900",
        "https://asrg.io/security-advisories/cve-2023-28900",
        "https://cveawg.mitre.org/api/cve/CVE-2023-28900"
    ],
    "affected": [
        {
            "vendor": "Škoda Auto",
            "product": "Škoda Connect",
            "versions": [
                {
                    "version": "0",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2023-28900",
        "koda",
        "Connect",
        "cloud",
        "VIN-to-user",
        "backend",
        "API",
        "Skoda",
        "Automotive",
        "contains",
        "Broken",
        "Access",
        "Control",
        "vulnerability",
        "allowing",
        "obtain",
        "nicknames",
        "other",
        "user",
        "identifiers",
        "service",
        "users",
        "specifying",
        "arbitrary",
        "number",
        "Škoda Auto",
        "Škoda Connect"
    ]
}


class Poc46CVE202328900ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-053'
    meta_poc_name = 'CVE-2023-28900 越权/信息泄露 Exposure Audit'
    meta_cve_id = 'CVE-2023-28900'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-28900'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

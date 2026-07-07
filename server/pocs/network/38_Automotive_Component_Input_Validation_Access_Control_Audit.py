#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 44,
    "cve": "CVE-2024-6287",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Automotive embedded component",
    "component": "车载软件组件",
    "type": "输入校验/访问控制",
    "summary": "ASRG披露的车载组件漏洞，关联智能汽车软件供应链。",
    "source_description": "Incorrect Calculation vulnerability in Renesas arm-trusted-firmware allows Local Execution of Code.\n\n\nWhen checking whether a new image invades/overlaps with a previously loaded image the code neglects to consider a few cases. that could An attacker to bypass memory range restriction and overwrite an already loaded image partly or completely, which could result in code execution and bypass of secure boot.",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6287",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-6287",
        "https://github.com/renesas-rcar/arm-trusted-firmware/commit/954d488a9798f8fda675c6b57c571b469b298f04",
        "https://asrg.io/security-advisories/cve-2024-6287/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-6287"
    ],
    "affected": [
        {
            "vendor": "Renesas",
            "product": "rcar_gen3_v2.5",
            "versions": [
                {
                    "version": "6a96c18c474e6339fab93f54d52aa7dcc4b70e52",
                    "status": "affected",
                    "lessThan": "954d488a9798f8fda675c6b57c571b469b298f04",
                    "versionType": "git"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-6287",
        "Automotive",
        "embedded",
        "component",
        "Incorrect",
        "Calculation",
        "vulnerability",
        "Renesas",
        "arm-trusted-firmware",
        "Local",
        "Execution",
        "Code",
        "When",
        "checking",
        "whether",
        "image",
        "invades",
        "overlaps",
        "previously",
        "loaded",
        "code",
        "neglects",
        "consider",
        "cases",
        "could",
        "bypass",
        "memory",
        "range",
        "restriction",
        "rcar_gen3_v2.5"
    ]
}


class Poc38CVE20246287AccessControlInputValidationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-044'
    meta_poc_name = 'CVE-2024-6287 输入校验/访问控制 Exposure Audit'
    meta_cve_id = 'CVE-2024-6287'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-6287'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

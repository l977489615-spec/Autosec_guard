#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 41,
    "cve": "CVE-2024-1633",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Automotive embedded component",
    "component": "车载软件组件",
    "type": "访问控制/输入校验",
    "summary": "ASRG披露的车载组件漏洞，影响智能车生态组件。",
    "source_description": "During the secure boot, bl2 (the second stage of\nthe bootloader) loops over images defined in the table “bl2_mem_params_descs”.\nFor each image, the bl2 reads the image length and destination from the image’s\ncertificate. Because of the way of reading from the image, which base on 32-bit unsigned integer value, it can result to an integer overflow. An attacker can bypass memory range restriction and write data out of buffer bounds, which could result in bypass of secure boot.\n\n Affected git version from c2f286820471ed276c57e603762bd831873e5a17 until (not \n",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1633",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-1633",
        "https://asrg.io/security-advisories/CVE-2024-1633/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-1633"
    ],
    "affected": [
        {
            "vendor": "Renesas",
            "product": "rcar_gen3_v2.5",
            "versions": [
                {
                    "version": "v2.5",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-1633",
        "Automotive",
        "embedded",
        "component",
        "During",
        "secure",
        "boot",
        "second",
        "stage",
        "bootloader",
        "loops",
        "over",
        "images",
        "defined",
        "table",
        "bl2_mem_params_descs",
        "each",
        "image",
        "reads",
        "length",
        "destination",
        "certificate",
        "Because",
        "reading",
        "which",
        "base",
        "unsigned",
        "integer",
        "value",
        "Renesas"
    ]
}


class Poc35CVE20241633AccessControlInputValidationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-041'
    meta_poc_name = 'CVE-2024-1633 访问控制/输入校验 Exposure Audit'
    meta_cve_id = 'CVE-2024-1633'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-1633'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 48,
    "cve": "CVE-2024-6564",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Renesas R-Car / ARM TF-A",
    "component": "rcar_dev_init",
    "type": "缓冲区溢出/安全启动绕过",
    "summary": "使用未验证镜像编号作循环计数，可导致安全启动绕过。",
    "source_description": "Buffer overflow in \"rcar_dev_init\"  due to using due to using untrusted data (rcar_image_number) as a loop counter before verifying it against RCAR_MAX_BL3X_IMAGE. This could lead to a full bypass of secure boot.",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6564",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-6564",
        "https://github.com/renesas-rcar/arm-trusted-firmware/commit/c9fb3558410032d2660c7f3b7d4b87dec09fe2f2",
        "https://asrg.io/security-advisories/cve-2024-6564/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-6564"
    ],
    "affected": [
        {
            "vendor": "Renesas",
            "product": "rcar_gen3_v2.5",
            "versions": [
                {
                    "version": "c2f286820471ed276c57e603762bd831873e5a17",
                    "status": "affected",
                    "lessThanOrEqual": "c9fb3558410032d2660c7f3b7d4b87dec09fe2f2",
                    "versionType": "git"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-6564",
        "Renesas",
        "R-Car",
        "ARM",
        "TF-A",
        "rcar_dev_init",
        "Buffer",
        "overflow",
        "using",
        "untrusted",
        "data",
        "rcar_image_number",
        "loop",
        "counter",
        "verifying",
        "against",
        "RCAR_MAX_BL3X_IMAGE",
        "could",
        "lead",
        "full",
        "bypass",
        "secure",
        "boot",
        "rcar_gen3_v2.5"
    ]
}


class Poc41CVE20246564ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-048'
    meta_poc_name = 'CVE-2024-6564 缓冲区溢出/安全启动绕过 Exposure Audit'
    meta_cve_id = 'CVE-2024-6564'
    meta_severity = 'High'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-6564'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 47,
    "cve": "CVE-2024-6563",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Renesas R-Car / ARM TF-A",
    "component": "secure boot",
    "type": "缓冲区拷贝越界",
    "summary": "启动链中输入长度未校验可能影响安全启动。",
    "source_description": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') vulnerability in Renesas arm-trusted-firmware allows Local Execution of Code. This vulnerability is associated with program files  https://github.Com/renesas-rcar/arm-trusted-firmware/blob/rcar_gen3_v2.5/drivers/renesas/common/io/i... https://github.Com/renesas-rcar/arm-trusted-firmware/blob/rcar_gen3_v2.5/drivers/renesas/common/io/io_rcar.C .\n\n\n\n\nIn line 313 \"addr_loaded_cnt\" is checked not to be \"CHECK_IMAGE_AREA_CNT\" (5) or larger, this check does not halt the function. Immediately after (line 317) there will be an overflow in the buffer and the value of \"dst\" will be written to the area immediately after the buffer, which is \"addr_loaded_cnt\". This will allow an attacker to freely control the value of \"addr_loaded_cnt\" and thus control the destination of the write immediately after (line 318). The write in line 318 will then be fully controlled by said attacker, with whichever address and whichever value (\"len\") they desire.",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6563",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-6563",
        "https://github.com/renesas-rcar/arm-trusted-firmware/commit/235f85b654a031f7647e81b86fc8e4ffeb430164",
        "https://asrg.io/security-advisories/cve-2024-6563/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-6563"
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
        "CVE-2024-6563",
        "Renesas",
        "R-Car",
        "ARM",
        "TF-A",
        "secure",
        "boot",
        "Buffer",
        "Copy",
        "without",
        "Checking",
        "Size",
        "Input",
        "Classic",
        "Overflow",
        "vulnerability",
        "arm-trusted-firmware",
        "Local",
        "Execution",
        "Code",
        "associated",
        "program",
        "files",
        "https",
        "github.Com",
        "renesas-rcar",
        "blob",
        "rcar_gen3_v2.5",
        "drivers",
        "renesas"
    ]
}


class Poc40CVE20246563OutOfBoundsAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-047'
    meta_poc_name = 'CVE-2024-6563 缓冲区拷贝越界 Exposure Audit'
    meta_cve_id = 'CVE-2024-6563'
    meta_severity = 'High'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-6563'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

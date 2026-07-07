#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 38,
    "cve": "CVE-2024-23960",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Alpine Halo9",
    "component": "固件元数据签名",
    "type": "签名校验不当",
    "summary": "物理攻击者可绕过签名校验，配合其他漏洞root代码执行。",
    "source_description": "Alpine Halo9 Improper Verification of Cryptographic Signature Vulnerability. This vulnerability allows physically present attackers to bypass signature validation mechanism on affected installations of Alpine Halo9 devices. Authentication is not required to exploit this vulnerability.\n\nThe specific flaw exists within the firmware metadata signature validation mechanism. The issue results from the lack of proper verification of a cryptographic signature. An attacker can leverage this in conjunction with other vulnerabilities to execute arbitrary code in the context of root.\n\nWas ZDI-CAN-23102",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23960",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23960",
        "https://www.zerodayinitiative.com/advisories/ZDI-24-845/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-23960"
    ],
    "affected": [
        {
            "vendor": "Alpine",
            "product": "Halo9",
            "versions": [
                {
                    "version": "6.0.000",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-23960",
        "Alpine",
        "Halo9",
        "Improper",
        "Verification",
        "Cryptographic",
        "Signature",
        "Vulnerability",
        "vulnerability",
        "physically",
        "present",
        "attackers",
        "bypass",
        "signature",
        "validation",
        "mechanism",
        "installations",
        "devices",
        "Authentication",
        "required",
        "exploit",
        "specific",
        "flaw",
        "exists"
    ]
}


class Poc32CVE202423960SignatureVerificationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-038'
    meta_poc_name = 'CVE-2024-23960 签名校验不当 Exposure Audit'
    meta_cve_id = 'CVE-2024-23960'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-23960'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

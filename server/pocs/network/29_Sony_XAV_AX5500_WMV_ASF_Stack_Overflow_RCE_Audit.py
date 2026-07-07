#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 35,
    "cve": "CVE-2024-23934",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Sony XAV-AX5500",
    "component": "WMV/ASF parser",
    "type": "栈溢出/RCE",
    "summary": "解析恶意WMV/ASF时栈溢出，需用户打开恶意文件或页面。",
    "source_description": "Sony XAV-AX5500 WMV/ASF Parsing Stack-based Buffer Overflow Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Sony XAV-AX5500 devices. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.\n\nThe specific flaw exists within the parsing of WMV/ASF files. A crafted Extended Content Description Object in a WMV media file can trigger an overflow of a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of the device.\n\n. Was ZDI-CAN-22994.",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23934",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23934",
        "https://www.zerodayinitiative.com/advisories/ZDI-24-875/",
        "https://www.sony.com/electronics/support/mobile-cd-players-digital-media-players-xav-series/xav-ax5500/software/00274156",
        "https://cveawg.mitre.org/api/cve/CVE-2024-23934"
    ],
    "affected": [
        {
            "vendor": "Sony",
            "product": "XAV-AX5500",
            "versions": [
                {
                    "version": "1.13",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-23934",
        "Sony",
        "XAV-AX5500",
        "WMV",
        "ASF",
        "parser",
        "RCE",
        "Parsing",
        "Stack-based",
        "Buffer",
        "Overflow",
        "Remote",
        "Code",
        "Execution",
        "Vulnerability",
        "vulnerability",
        "remote",
        "attackers",
        "execute",
        "arbitrary",
        "code",
        "installations",
        "devices",
        "User",
        "interaction",
        "required",
        "exploit"
    ]
}


class Poc29CVE202423934StackOverflowRCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-035'
    meta_poc_name = 'CVE-2024-23934 栈溢出/RCE Exposure Audit'
    meta_cve_id = 'CVE-2024-23934'
    meta_severity = 'High'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-23934'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

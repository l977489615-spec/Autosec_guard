#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 40,
    "cve": "CVE-2024-23972",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Sony XAV-AX5500",
    "component": "USB配置描述符",
    "type": "栈溢出/RCE",
    "summary": "恶意USB配置描述符触发固定长度缓冲区溢出并执行代码。",
    "source_description": "Sony XAV-AX5500 USB Configuration Descriptor Buffer Overflow Remote Code Execution Vulnerability. This vulnerability allows physically present attackers to execute arbitrary code on affected installations of Sony XAV-AX5500 devices. Authentication is not required to exploit this vulnerability.\n\nThe specific flaw exists within the USB host driver. A crafted USB configuration descriptor can trigger an overflow of a fixed-length buffer. An attacker can leverage this vulnerability to execute code in the context of the device.\n\nWas ZDI-CAN-23185",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23972",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23972",
        "https://www.zerodayinitiative.com/advisories/ZDI-24-876/",
        "https://www.sony.com/electronics/support/mobile-cd-players-digital-media-players-xav-series/xav-ax5500/software/00274156",
        "https://cveawg.mitre.org/api/cve/CVE-2024-23972"
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
        "CVE-2024-23972",
        "Sony",
        "XAV-AX5500",
        "USB",
        "RCE",
        "Configuration",
        "Descriptor",
        "Buffer",
        "Overflow",
        "Remote",
        "Code",
        "Execution",
        "Vulnerability",
        "vulnerability",
        "physically",
        "present",
        "attackers",
        "execute",
        "arbitrary",
        "code",
        "installations",
        "devices",
        "Authentication",
        "required",
        "exploit",
        "specific"
    ]
}


class Poc34CVE202423972StackOverflowRCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-040'
    meta_poc_name = 'CVE-2024-23972 栈溢出/RCE Exposure Audit'
    meta_cve_id = 'CVE-2024-23972'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-23972'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

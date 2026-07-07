#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 43,
    "cve": "CVE-2024-6245",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Maruti Suzuki SmartPlay",
    "component": "Linux infotainment hub",
    "type": "默认凭据",
    "summary": "SmartPlay IVI使用默认凭据，攻击者可尝试常见用户名/密码。",
    "source_description": "Use of Default Credentials vulnerability in Maruti Suzuki SmartPlay on Linux (Infotainment Hub modules) allows attacker to try common or default usernames and passwords.The issue was detected on a 2022 Maruti Suzuki Brezza in India Market.\n\nThis issue affects SmartPlay: 66T0.05.50.",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6245",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-6245",
        "https://www.marutisuzuki.com/corporate/technology/smartplay-systems",
        "https://www.global-infotainment-system.com/en/top.html",
        "https://cveawg.mitre.org/api/cve/CVE-2024-6245"
    ],
    "affected": [
        {
            "vendor": "Faurecia Clarion Electronics Co., Ltd.",
            "product": "SmartPlay",
            "versions": [
                {
                    "version": "66T0.05.50",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-6245",
        "Maruti",
        "Suzuki",
        "SmartPlay",
        "Linux",
        "infotainment",
        "hub",
        "Default",
        "Credentials",
        "vulnerability",
        "Infotainment",
        "modules",
        "common",
        "default",
        "usernames",
        "passwords.The",
        "issue",
        "detected",
        "Brezza",
        "India",
        "Market",
        "affects",
        "T0.05.50",
        "Faurecia Clarion Electronics Co., Ltd"
    ]
}


class Poc37CVE20246245ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-043'
    meta_poc_name = 'CVE-2024-6245 默认凭据 Exposure Audit'
    meta_cve_id = 'CVE-2024-6245'
    meta_severity = 'Medium'
    meta_protocol = 'https'
    meta_target_os = ['linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-6245'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

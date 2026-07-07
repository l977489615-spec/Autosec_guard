#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 42,
    "cve": "CVE-2024-5684",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Automotive embedded component",
    "component": "车载软件组件",
    "type": "内存安全/配置问题",
    "summary": "ASRG披露的车载组件漏洞，需结合公告复核具体攻击面。",
    "source_description": "An attacker with access to the private network (the charger is connected to) or local access to the Ethernet-Interface can exploit a faulty implementation of the JWT-library in order to bypass the password authentication to the web configuration interface and then has full access as the user would have. However, an attacker will not have developer or admin rights. If the implementation of the JWT-library is wrongly configured to accept \"none\"-algorithms, the server will pass insecure JWT. A local, unauthenticated attacker can exploit this vulnerability to bypass the authentication mechanism.",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-5684",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-5684",
        "https://asrg.io/security-advisories/vulnerability-in-id-charger-connect-and-pro-from-volkswagen-group-charging-gmbh-elli-evbox-versions-spr3-2b-spr3-51-and-spr3-52/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-5684"
    ],
    "affected": [
        {
            "vendor": "Volkswagen Group Charging GmbH - Elli, EVBox",
            "product": "ID Charger Connect & Pro",
            "versions": [
                {
                    "version": "SPR3.2B",
                    "status": "affected"
                },
                {
                    "version": "SPR3.51",
                    "status": "affected"
                },
                {
                    "version": "SPR3.52",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-5684",
        "Automotive",
        "embedded",
        "component",
        "access",
        "private",
        "network",
        "charger",
        "connected",
        "local",
        "Ethernet-Interface",
        "exploit",
        "faulty",
        "implementation",
        "JWT-library",
        "order",
        "bypass",
        "password",
        "authentication",
        "configuration",
        "interface",
        "then",
        "full",
        "user",
        "would",
        "have",
        "However",
        "will",
        "Volkswagen Group Charging GmbH - Elli, EVBox",
        "ID Charger Connect & Pro"
    ]
}


class Poc36CVE20245684ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-042'
    meta_poc_name = 'CVE-2024-5684 内存安全/配置问题 Exposure Audit'
    meta_cve_id = 'CVE-2024-5684'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-5684'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

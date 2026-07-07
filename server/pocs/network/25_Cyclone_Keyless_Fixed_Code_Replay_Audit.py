#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 17,
    "cve": "CVE-2025-6030",
    "year": 2025,
    "domain": "IVI/OS/协议/隐私",
    "vendor_product": "Cyclone Matrix TRF smart keyless entry",
    "component": "Key fob transmitter",
    "type": "固定学习码/重放",
    "summary": "2024 KIA Soluto等车型的售后无钥匙系统使用固定学习码，可被重放。",
    "source_description": "Use of fixed learning codes, one code to lock the car and the other code to unlock it, in the Key Fob Transmitter in Cyclone Matrix TRF Smart  Keyless Entry System, which allows a replay attack.\n\nResearch was completed on the 2024 KIA Soluto.  Attack confirmed on other KIA Models in Ecuador.",
    "poc_status": "有公开研究文章/攻击演示",
    "research_value": "车载OS/多媒体/无钥匙系统供应链风险。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-6030",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-6030",
        "https://revers3everything.com/unlocking-thousands-of-cars-by-exploiting-learning-codes-from-key-fobs/",
        "https://asrg.io/security-advisories/cve-2025-6030-autoeastern-smart-keyless-entry-system-replay-attack/",
        "https://cveawg.mitre.org/api/cve/CVE-2025-6030"
    ],
    "affected": [
        {
            "vendor": "Autoeastern",
            "product": "Cyclone Matrix TRF",
            "versions": [
                {
                    "version": "2024",
                    "status": "affected",
                    "lessThanOrEqual": "2025",
                    "versionType": "date"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-6030",
        "Cyclone",
        "Matrix",
        "TRF",
        "smart",
        "keyless",
        "entry",
        "Key",
        "fob",
        "transmitter",
        "fixed",
        "learning",
        "codes",
        "code",
        "lock",
        "other",
        "unlock",
        "Transmitter",
        "Smart",
        "Keyless",
        "Entry",
        "System",
        "which",
        "replay",
        "attack",
        "Research",
        "completed",
        "Soluto",
        "Attack",
        "confirmed"
    ]
}


class Poc25CVE20256030ReplayAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-017'
    meta_poc_name = 'CVE-2025-6030 固定学习码/重放 Exposure Audit'
    meta_cve_id = 'CVE-2025-6030'
    meta_severity = 'Critical'
    meta_protocol = 'rf'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-6030'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

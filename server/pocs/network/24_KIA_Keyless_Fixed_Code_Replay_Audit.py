#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 16,
    "cve": "CVE-2025-6029",
    "year": 2025,
    "domain": "IVI/OS/协议/隐私",
    "vendor_product": "KIA-branded aftermarket smart keyless entry",
    "component": "Key fob transmitter",
    "type": "固定学习码/重放",
    "summary": "固定开锁/上锁学习码导致重放攻击，主要在厄瓜多尔售后KIA套件中披露。",
    "source_description": "Use of fixed learning codes, one code to lock the car and the other code to unlock it, the Key Fob Transmitter in KIA-branded Aftermarket Generic Smart  Keyless Entry System, primarily distributed in Ecuador, which allows a replay attack.\n\nManufacture is unknown at the time of release.  CVE Record will be updated once this is clarified.",
    "poc_status": "有公开研究文章/攻击演示",
    "research_value": "车载OS/多媒体/无钥匙系统供应链风险。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-6029",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-6029",
        "https://revers3everything.com/unlocking-thousands-of-cars-by-exploiting-learning-codes-from-key-fobs/",
        "https://asrg.io/security-advisories/cve-2025-6029-kia-branded-aftermarket-generic-smart-keyless-entry-system-replay-attack/",
        "https://cveawg.mitre.org/api/cve/CVE-2025-6029"
    ],
    "affected": [
        {
            "vendor": "KIA",
            "product": "Aftermarket Generic Smart Keyless Entry System",
            "versions": [
                {
                    "version": "KIA Ecuador Key Fobs version 2022/2023",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-6029",
        "KIA-branded",
        "aftermarket",
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
        "Aftermarket",
        "Generic",
        "Smart",
        "Keyless",
        "Entry",
        "System",
        "primarily",
        "distributed",
        "Ecuador",
        "which",
        "replay",
        "attack",
        "Manufacture"
    ]
}


class Poc24CVE20256029ReplayAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-016'
    meta_poc_name = 'CVE-2025-6029 固定学习码/重放 Exposure Audit'
    meta_cve_id = 'CVE-2025-6029'
    meta_severity = 'Critical'
    meta_protocol = 'rf'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-6029'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

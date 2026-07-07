#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 14,
    "cve": "CVE-2026-49322",
    "year": 2026,
    "domain": "协议/RF/RKES",
    "vendor_product": "Automotive RF/RKES",
    "component": "Key fob / RF protocol",
    "type": "弱加密/重放",
    "summary": "弱认证和风险加密算法导致捕获-重放可行。",
    "source_description": "Weak authentication in the Wireless Control Module (WCM) of the Indian Motorcycle Scout Bobber + Tech 2025 model year allows an adjacent-network attacker with read access to the in-vehicle network to recover the user-set unlock PIN by passively observing a single PIN authentication exchange. The Infotainment Digital Round display computes its response using a non-cryptographic operation rather than a cryptographic challenge-response, so the PIN is mathematically derivable from one captured exchange, defeating the motorcycle's primary user-authentication control. Specific protocol details have been withheld pending vendor remediation.",
    "poc_status": "有公开安全公告；部分有研究演示，未见通用武器化PoC",
    "research_value": "适合车钥匙RF协议、滚动码/回滚检测、防重放机制研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-49322",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-49322",
        "https://www.asrg.io/security-advisories/cve-2026-49322-indian-scout-infotainment-wcm-weak-authentication",
        "https://cveawg.mitre.org/api/cve/CVE-2026-49322"
    ],
    "affected": [
        {
            "vendor": "Indian Motorcycle",
            "product": "Scout Bobber + Tech",
            "versions": [
                {
                    "version": "2025",
                    "status": "affected",
                    "versionType": "model-year"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2026-49322",
        "Automotive",
        "RKES",
        "Key",
        "fob",
        "protocol",
        "Weak",
        "authentication",
        "Wireless",
        "Control",
        "Module",
        "Indian",
        "Motorcycle",
        "Scout",
        "Bobber",
        "Tech",
        "model",
        "year",
        "adjacent-network",
        "read",
        "access",
        "in-vehicle",
        "network",
        "recover",
        "user-set",
        "unlock",
        "passively",
        "observing",
        "single",
        "exchange"
    ]
}


class Poc40CVE202649322ReplayCryptoAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-014'
    meta_poc_name = 'CVE-2026-49322 弱加密/重放 Exposure Audit'
    meta_cve_id = 'CVE-2026-49322'
    meta_severity = 'High'
    meta_protocol = 'rf'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['rf']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2026-49322'
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 15,
    "cve": "CVE-2026-49324",
    "year": 2026,
    "domain": "协议/RF/RKES",
    "vendor_product": "Automotive RF/RKES",
    "component": "Key fob / RF protocol",
    "type": "认证节流不足",
    "summary": "认证尝试限制不足与资源消耗问题，可用于暴力/DoS。",
    "source_description": "Uncontrolled resource consumption in the Wireless Control Module (WCM) of the Indian Motorcycle Scout Bobber + Tech 2025 model year allows an adjacent-network attacker with write access to the in-vehicle network to permanently immobilize the motorcycle. The WCM enforces a brute-force lockout on the immobilizer authentication algorithm, but the lockout counter is reachable by any unauthenticated message, has no session binding, and does not reset on power cycle. An attacker can deliberately trip the lockout with a small number of crafted frames, leaving the bike un-startable until dealer service. Specific thresholds have been withheld pending vendor remediation.",
    "poc_status": "有公开安全公告；部分有研究演示，未见通用武器化PoC",
    "research_value": "适合车钥匙RF协议、滚动码/回滚检测、防重放机制研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-49324",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-49324",
        "https://www.asrg.io/security-advisories/cve-2026-49324-indian-scout-wcm-bruteforce-lockout-dos",
        "https://cveawg.mitre.org/api/cve/CVE-2026-49324"
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
        "CVE-2026-49324",
        "Automotive",
        "RKES",
        "Key",
        "fob",
        "protocol",
        "Uncontrolled",
        "resource",
        "consumption",
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
        "write",
        "access",
        "in-vehicle",
        "network",
        "permanently",
        "immobilize",
        "motorcycle",
        "enforces",
        "brute-force",
        "lockout"
    ]
}


class Poc41CVE202649324ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-015'
    meta_poc_name = 'CVE-2026-49324 认证节流不足 Exposure Audit'
    meta_cve_id = 'CVE-2026-49324'
    meta_severity = 'High'
    meta_protocol = 'rf'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['rf']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2026-49324'
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

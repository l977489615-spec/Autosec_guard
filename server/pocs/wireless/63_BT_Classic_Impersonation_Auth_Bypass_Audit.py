#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 78,
    "cve": "CVE-2020-26555",
    "year": 2020,
    "domain": "蓝牙/协议",
    "vendor_product": "Bluetooth BR/EDR",
    "component": "Impersonation",
    "type": "认证绕过",
    "summary": "Bluetooth Classic冒充攻击，影响配对信任模型。",
    "source_description": "Bluetooth legacy BR/EDR PIN code pairing in Bluetooth Core Specification 1.0B through 5.2 may permit an unauthenticated nearby device to spoof the BD_ADDR of the peer device to complete pairing without knowledge of the PIN.",
    "poc_status": "有公开研究/PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-26555",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-26555",
        "https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/reporting-security/",
        "https://kb.cert.org/vuls/id/799380",
        "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NSS6CTGE4UGTJLCOZOASDR3T3SLL6QJZ/",
        "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00520.html",
        "https://cveawg.mitre.org/api/cve/CVE-2020-26555"
    ],
    "affected": [
        {
            "vendor": "n/a",
            "product": "n/a",
            "versions": [
                {
                    "version": "n/a",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2020-26555",
        "Bluetooth",
        "EDR",
        "Impersonation",
        "legacy",
        "code",
        "pairing",
        "Core",
        "Specification",
        "permit",
        "unauthenticated",
        "nearby",
        "device",
        "spoof",
        "BD_ADDR",
        "peer",
        "complete",
        "without",
        "knowledge",
        "PIN"
    ]
}


class Poc63CVE202026555AuthBypassAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-078'
    meta_poc_name = 'CVE-2020-26555 认证绕过 Exposure Audit'
    meta_cve_id = 'CVE-2020-26555'
    meta_severity = 'High'
    meta_protocol = 'bluetooth'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2020-26555'
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

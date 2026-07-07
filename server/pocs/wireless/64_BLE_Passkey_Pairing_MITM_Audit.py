#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 79,
    "cve": "CVE-2020-26558",
    "year": 2020,
    "domain": "蓝牙/协议",
    "vendor_product": "Bluetooth LE",
    "component": "Passkey Entry",
    "type": "配对绕过/中间人",
    "summary": "BLE配对过程可被中间人/冒充影响。",
    "source_description": "Bluetooth LE and BR/EDR secure pairing in Bluetooth Core Specification 2.1 through 5.2 may permit a nearby man-in-the-middle attacker to identify the Passkey used during pairing (in the Passkey authentication procedure) by reflection of the public key and the authentication evidence of the initiating device, potentially permitting this attacker to complete authenticated pairing with the responding device using the correct Passkey for the pairing session. The attack methodology determines the Passkey value one bit at a time.",
    "poc_status": "有公开研究/PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-26558",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-26558",
        "https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/reporting-security/",
        "https://kb.cert.org/vuls/id/799380",
        "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NSS6CTGE4UGTJLCOZOASDR3T3SLL6QJZ/",
        "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00520.html",
        "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00517.html",
        "https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html",
        "https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html",
        "https://lists.debian.org/debian-lts-announce/2021/06/msg00022.html",
        "https://www.debian.org/security/2021/dsa-4951",
        "https://security.gentoo.org/glsa/202209-16",
        "https://cveawg.mitre.org/api/cve/CVE-2020-26558"
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
        "CVE-2020-26558",
        "Bluetooth",
        "Passkey",
        "Entry",
        "secure",
        "pairing",
        "Core",
        "Specification",
        "permit",
        "nearby",
        "man-in-the-middle",
        "identify",
        "used",
        "during",
        "authentication",
        "procedure",
        "reflection",
        "public",
        "evidence",
        "initiating",
        "device",
        "potentially",
        "permitting",
        "complete"
    ]
}


class Poc64CVE202026558ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-079'
    meta_poc_name = 'CVE-2020-26558 配对绕过/中间人 Exposure Audit'
    meta_cve_id = 'CVE-2020-26558'
    meta_severity = 'High'
    meta_protocol = 'bluetooth'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2020-26558'
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

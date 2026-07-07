#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 77,
    "cve": "CVE-2020-10135",
    "year": 2020,
    "domain": "蓝牙/协议",
    "vendor_product": "Bluetooth BR/EDR",
    "component": "BIAS",
    "type": "认证绕过",
    "summary": "Bluetooth BIAS攻击可冒充已配对设备。",
    "source_description": "Legacy pairing and secure-connections pairing authentication in Bluetooth BR/EDR Core Specification v5.2 and earlier may allow an unauthenticated user to complete authentication without pairing credentials via adjacent access. An unauthenticated, adjacent attacker could impersonate a Bluetooth BR/EDR master or slave to pair with a previously paired remote device to successfully complete the authentication procedure without knowing the link key.",
    "poc_status": "有公开研究/PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-10135",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-10135",
        "https://kb.cert.org/vuls/id/647177/",
        "http://seclists.org/fulldisclosure/2020/Jun/5",
        "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00009.html",
        "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00047.html",
        "https://francozappa.github.io/about-bias/",
        "https://www.bluetooth.com/learn-about-bluetooth/bluetooth-technology/bluetooth-security/bias-vulnerability/",
        "http://packetstormsecurity.com/files/157922/Bluetooth-Impersonation-Attack-BIAS-Proof-Of-Concept.html",
        "https://cveawg.mitre.org/api/cve/CVE-2020-10135"
    ],
    "affected": [
        {
            "vendor": "Bluetooth",
            "product": "BR/EDR",
            "versions": [
                {
                    "version": "5.2",
                    "status": "affected",
                    "lessThanOrEqual": "5.2",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2020-10135",
        "Bluetooth",
        "EDR",
        "BIAS",
        "Legacy",
        "pairing",
        "secure-connections",
        "authentication",
        "Core",
        "Specification",
        "v5.2",
        "earlier",
        "allow",
        "unauthenticated",
        "user",
        "complete",
        "without",
        "credentials",
        "adjacent",
        "access",
        "could",
        "impersonate",
        "master",
        "slave",
        "pair",
        "BR/EDR"
    ]
}


class Poc62CVE202010135AuthBypassAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-077'
    meta_poc_name = 'CVE-2020-10135 认证绕过 Exposure Audit'
    meta_cve_id = 'CVE-2020-10135'
    meta_severity = 'High'
    meta_protocol = 'bluetooth'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2020-10135'
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

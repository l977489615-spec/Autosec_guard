#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 66,
    "cve": "CVE-2017-0785",
    "year": 2017,
    "domain": "蓝牙/移动-车机互联",
    "vendor_product": "Android Bluetooth",
    "component": "Bluetooth SDP",
    "type": "BlueBorne信息泄露",
    "summary": "BlueBorne蓝牙SDP信息泄露，可辅助攻击链。",
    "source_description": "A information disclosure vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146698.",
    "poc_status": "有公开PoC/研究代码",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-0785",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2017-0785",
        "http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html",
        "http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html",
        "https://source.android.com/security/bulletin/2017-09-01",
        "http://www.securitytracker.com/id/1041300",
        "http://www.securityfocus.com/bid/100812",
        "https://cveawg.mitre.org/api/cve/CVE-2017-0785"
    ],
    "affected": [
        {
            "vendor": "Google Inc.",
            "product": "Android",
            "versions": [
                {
                    "version": "4.4.4",
                    "status": "affected"
                },
                {
                    "version": "5.0.2",
                    "status": "affected"
                },
                {
                    "version": "5.1.1",
                    "status": "affected"
                },
                {
                    "version": "6.0",
                    "status": "affected"
                },
                {
                    "version": "6.0.1",
                    "status": "affected"
                },
                {
                    "version": "7.0",
                    "status": "affected"
                },
                {
                    "version": "7.1.1",
                    "status": "affected"
                },
                {
                    "version": "7.1.2",
                    "status": "affected"
                },
                {
                    "version": "8.0",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2017-0785",
        "Android",
        "Bluetooth",
        "SDP",
        "BlueBorne",
        "information",
        "disclosure",
        "vulnerability",
        "system",
        "bluetooth",
        "A-63146698",
        "Google Inc"
    ]
}


class Poc51CVE20170785BlueBorneAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-066'
    meta_poc_name = 'CVE-2017-0785 BlueBorne信息泄露 Exposure Audit'
    meta_cve_id = 'CVE-2017-0785'
    meta_severity = 'Medium'
    meta_protocol = 'bluetooth'
    meta_target_os = ['android']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2017-0785'
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

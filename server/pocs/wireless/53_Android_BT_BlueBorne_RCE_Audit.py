#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 68,
    "cve": "CVE-2017-0782",
    "year": 2017,
    "domain": "蓝牙/移动-车机互联",
    "vendor_product": "Android Bluetooth",
    "component": "Bluetooth stack",
    "type": "BlueBorne RCE",
    "summary": "BlueBorne蓝牙RCE，影响车载Android/手机投屏生态。",
    "source_description": "A remote code execution vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146237.",
    "poc_status": "有公开PoC/研究代码",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-0782",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2017-0782",
        "http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html",
        "https://source.android.com/security/bulletin/2017-09-01",
        "http://www.securityfocus.com/bid/100822",
        "https://cveawg.mitre.org/api/cve/CVE-2017-0782"
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
        "CVE-2017-0782",
        "Android",
        "Bluetooth",
        "stack",
        "BlueBorne",
        "RCE",
        "remote",
        "code",
        "execution",
        "vulnerability",
        "system",
        "bluetooth",
        "A-63146237",
        "Google Inc"
    ]
}


class Poc53CVE20170782RCEBlueBorneAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-068'
    meta_poc_name = 'CVE-2017-0782 BlueBorne RCE Exposure Audit'
    meta_cve_id = 'CVE-2017-0782'
    meta_severity = 'Critical'
    meta_protocol = 'bluetooth'
    meta_target_os = ['android']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2017-0782'
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

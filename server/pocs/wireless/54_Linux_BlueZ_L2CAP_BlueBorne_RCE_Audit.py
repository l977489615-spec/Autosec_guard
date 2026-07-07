#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 69,
    "cve": "CVE-2017-1000251",
    "year": 2017,
    "domain": "蓝牙/Linux车机",
    "vendor_product": "Linux BlueZ",
    "component": "L2CAP",
    "type": "BlueBorne内核RCE",
    "summary": "Linux蓝牙L2CAP缺陷，可影响Linux/AGL类车机。",
    "source_description": "The native Bluetooth stack in the Linux Kernel (BlueZ), starting at the Linux kernel version 2.6.32 and up to and including 4.13.1, are vulnerable to a stack overflow vulnerability in the processing of L2CAP configuration responses resulting in Remote code execution in kernel space.",
    "poc_status": "有公开PoC/研究代码",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000251",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2017-1000251",
        "https://access.redhat.com/errata/RHSA-2017:2732",
        "https://www.exploit-db.com/exploits/42762/",
        "https://access.redhat.com/errata/RHSA-2017:2705",
        "https://access.redhat.com/errata/RHSA-2017:2683",
        "https://access.redhat.com/errata/RHSA-2017:2704",
        "https://access.redhat.com/errata/RHSA-2017:2682",
        "https://access.redhat.com/security/vulnerabilities/blueborne",
        "https://www.armis.com/blueborne",
        "http://www.securitytracker.com/id/1039373",
        "https://access.redhat.com/errata/RHSA-2017:2731",
        "https://cveawg.mitre.org/api/cve/CVE-2017-1000251"
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
        "CVE-2017-1000251",
        "Linux",
        "BlueZ",
        "L2CAP",
        "BlueBorne",
        "RCE",
        "native",
        "Bluetooth",
        "stack",
        "Kernel",
        "starting",
        "kernel",
        "including",
        "vulnerable",
        "overflow",
        "vulnerability",
        "processing",
        "configuration",
        "responses",
        "resulting",
        "Remote",
        "code",
        "execution",
        "space"
    ]
}


class Poc54CVE20171000251RCEBlueBorneAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-069'
    meta_poc_name = 'CVE-2017-1000251 BlueBorne内核RCE Exposure Audit'
    meta_cve_id = 'CVE-2017-1000251'
    meta_severity = 'High'
    meta_protocol = 'bluetooth'
    meta_target_os = ['linux']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2017-1000251'
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

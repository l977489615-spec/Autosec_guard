#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 61,
    "cve": "CVE-2021-22156",
    "year": 2021,
    "domain": "车载OS/QNX",
    "vendor_product": "BlackBerry QNX SDP/OS for Safety",
    "component": "calloc() C runtime",
    "type": "整数溢出/RCE或DoS",
    "summary": "BadAlloc：QNX calloc整数溢出，可DoS或代码执行。",
    "source_description": "An integer overflow vulnerability in the calloc() function of the C runtime library of affected versions of BlackBerry® QNX Software Development Platform (SDP) version(s) 6.5.0SP1 and earlier, QNX OS for Medical 1.1 and earlier, and QNX OS for Safety 1.0.1 and earlier that could allow an attacker to potentially perform a denial of service or execute arbitrary code.",
    "poc_status": "有CISA/研究公告，未见通用车载PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-22156",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-22156",
        "https://support.blackberry.com/kb/articleDetail?articleNumber=000082334",
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-qnx-TOxjVPdL",
        "https://cveawg.mitre.org/api/cve/CVE-2021-22156"
    ],
    "affected": [
        {
            "vendor": "BlackBerry",
            "product": "QNX Software Development Platform (SDP), QNX OS for Medical and QNX OS for Safety",
            "versions": [
                {
                    "version": "QNX SDP 6.5.0 SP1 and earlier",
                    "status": "affected"
                },
                {
                    "version": "QNX OS for Medical 1.1 and earlier",
                    "status": "affected"
                },
                {
                    "version": "QNX OS for Safety 1.0.1 and earlier",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2021-22156",
        "BlackBerry",
        "QNX",
        "SDP",
        "Safety",
        "calloc",
        "runtime",
        "RCE",
        "DoS",
        "integer",
        "overflow",
        "vulnerability",
        "function",
        "library",
        "Software",
        "Development",
        "Platform",
        "earlier",
        "Medical",
        "could",
        "allow",
        "potentially",
        "perform",
        "denial",
        "service",
        "execute",
        "arbitrary",
        "code",
        "QNX Software Development Platform (SDP), QNX OS for Medical and QNX OS for Safety"
    ]
}


class Poc25CVE202122156RCEDoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-061'
    meta_poc_name = 'CVE-2021-22156 整数溢出/RCE或DoS Exposure Audit'
    meta_cve_id = 'CVE-2021-22156'
    meta_severity = 'Critical'
    meta_protocol = 'local'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2021-22156'
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

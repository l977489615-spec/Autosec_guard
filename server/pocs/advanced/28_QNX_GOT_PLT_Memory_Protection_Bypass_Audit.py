#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 64,
    "cve": "CVE-2017-3893",
    "year": 2017,
    "domain": "车载OS/QNX",
    "vendor_product": "BlackBerry QNX SDP",
    "component": "GOT/PLT protection",
    "type": "内存保护绕过",
    "summary": "默认配置未能始终阻止攻击者通过溢出修改GOT/PLT。",
    "source_description": "In BlackBerry QNX Software Development Platform (SDP) 6.6.0, the default configuration of the QNX SDP system did not in all circumstances prevent attackers from modifying the GOT or PLT tables with buffer overflow attacks.",
    "poc_status": "未见公开PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-3893",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2017-3893",
        "http://support.blackberry.com/kb/articleDetail?articleNumber=000046674",
        "https://cveawg.mitre.org/api/cve/CVE-2017-3893"
    ],
    "affected": [
        {
            "vendor": "BlackBerry",
            "product": "QNX Software Development Platform (QNX SDP)",
            "versions": [
                {
                    "version": "6.6.0",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2017-3893",
        "BlackBerry",
        "QNX",
        "SDP",
        "GOT",
        "PLT",
        "protection",
        "Software",
        "Development",
        "Platform",
        "default",
        "configuration",
        "system",
        "circumstances",
        "prevent",
        "attackers",
        "modifying",
        "tables",
        "buffer",
        "overflow",
        "attacks",
        "QNX Software Development Platform (QNX SDP"
    ]
}


class Poc28CVE20173893ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-064'
    meta_poc_name = 'CVE-2017-3893 内存保护绕过 Exposure Audit'
    meta_cve_id = 'CVE-2017-3893'
    meta_severity = 'High'
    meta_protocol = 'local'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2017-3893'
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

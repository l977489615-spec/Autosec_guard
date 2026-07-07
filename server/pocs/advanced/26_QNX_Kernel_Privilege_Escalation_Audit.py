#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 62,
    "cve": "CVE-2021-32025",
    "year": 2021,
    "domain": "车载OS/QNX",
    "vendor_product": "BlackBerry QNX Neutrino Kernel",
    "component": "Kernel",
    "type": "权限提升",
    "summary": "QNX内核权限提升，可访问数据、改变行为或崩溃系统。",
    "source_description": "An elevation of privilege vulnerability in the QNX Neutrino Kernel of affected versions of QNX Software Development Platform version(s) 6.4.0 to 7.0, QNX Momentics all 6.3.x versions, QNX OS for Safety versions 1.0.0 to 1.0.2, QNX OS for Safety versions 2.0.0 to 2.0.1, QNX for Medical versions 1.0.0 to 1.1.1, and QNX OS for Medical version 2.0.0 could allow an attacker to potentially access data, modify behavior, or permanently crash the system.",
    "poc_status": "未见公开PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-32025",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-32025",
        "http://support.blackberry.com/kb/articleDetail?articleNumber=000090868",
        "https://cveawg.mitre.org/api/cve/CVE-2021-32025"
    ],
    "affected": [
        {
            "vendor": "BlackBerry",
            "product": "QNX Software Development Platform (SDP), QNX OS for Medical (QOSM), and QNX OS for Safety (QOS)",
            "versions": [
                {
                    "version": "QNX SDP 6.4.0 to 7.0",
                    "status": "affected"
                },
                {
                    "version": "QNX Momentics all 6.3.x versions",
                    "status": "affected"
                },
                {
                    "version": "QNX OS for Safety versions 1.0.0 to 1.0.2 safety products compliant with IEC 61508 and/or ISO 26262",
                    "status": "affected"
                },
                {
                    "version": "QNX OS for Safety versions 2.0.0 to 2.0.1 safety products compliant with IEC 61508 and/or ISO 26262",
                    "status": "affected"
                },
                {
                    "version": "QNX OS for Medical versions 1.0.0 to 1.1.1 safety products compliant with IEC 62304",
                    "status": "affected"
                },
                {
                    "version": "QNX OS for Medical versions 2.0.0 safety product compliant with IEC 62304",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2021-32025",
        "BlackBerry",
        "QNX",
        "Neutrino",
        "Kernel",
        "elevation",
        "privilege",
        "vulnerability",
        "Software",
        "Development",
        "Platform",
        "Momentics",
        "Safety",
        "Medical",
        "could",
        "allow",
        "potentially",
        "access",
        "data",
        "modify",
        "behavior",
        "permanently",
        "QNX Software Development Platform (SDP), QNX OS for Medical (QOSM), and QNX OS for Safety (QOS"
    ]
}


class Poc26CVE202132025PrivilegeEscalationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-062'
    meta_poc_name = 'CVE-2021-32025 权限提升 Exposure Audit'
    meta_cve_id = 'CVE-2021-32025'
    meta_severity = 'High'
    meta_protocol = 'local'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2021-32025'
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

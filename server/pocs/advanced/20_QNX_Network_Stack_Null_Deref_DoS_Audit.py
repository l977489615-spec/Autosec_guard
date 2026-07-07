#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 29,
    "cve": "CVE-2024-35215",
    "year": 2024,
    "domain": "车载OS/QNX",
    "vendor_product": "BlackBerry QNX SDP",
    "component": "Networking Stack",
    "type": "空指针/DoS",
    "summary": "QNX SDP 7.1/7.0 IP socket options处理空指针，本地可DoS。",
    "source_description": "NULL pointer dereference in IP socket options processing of the Networking Stack in QNX Software Development Platform (SDP) version(s) 7.1 and 7.0 could allow an attacker with local access to cause a denial-of-service condition in the context of the Networking Stack process.",
    "poc_status": "未见公开PoC；供应商公告",
    "research_value": "QNX广泛用于IVI、ADAS和域控制器，属于车载基础软件风险。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-35215",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-35215",
        "https://support.blackberry.com/pkb/s/article/140162",
        "https://cveawg.mitre.org/api/cve/CVE-2024-35215"
    ],
    "affected": [
        {
            "vendor": "BlackBerry",
            "product": "QNX Software Development Platform (SDP)",
            "versions": [
                {
                    "version": "7.0",
                    "status": "affected",
                    "lessThanOrEqual": "7.1",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-35215",
        "BlackBerry",
        "QNX",
        "SDP",
        "Networking",
        "Stack",
        "DoS",
        "NULL",
        "pointer",
        "dereference",
        "socket",
        "options",
        "processing",
        "Software",
        "Development",
        "Platform",
        "could",
        "allow",
        "local",
        "access",
        "cause",
        "denial-of-service",
        "condition",
        "context",
        "process",
        "QNX Software Development Platform (SDP"
    ]
}


class Poc20CVE202435215NullDerefDoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-029'
    meta_poc_name = 'CVE-2024-35215 空指针/DoS Exposure Audit'
    meta_cve_id = 'CVE-2024-35215'
    meta_severity = 'High'
    meta_protocol = 'local'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-35215'
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 20,
    "cve": "CVE-2025-8090",
    "year": 2025,
    "domain": "IVI/OS/协议/隐私",
    "vendor_product": "BlackBerry QNX SDP / Neutrino Kernel",
    "component": "Kernel",
    "type": "空指针引用/DoS",
    "summary": "QNX Neutrino Kernel空指针引用导致本地拒绝服务。",
    "source_description": "Null pointer dereference in the MsgRegisterEvent() system call could allow an attacker with local access and code execution abilities to crash the QNX Neutrino kernel.",
    "poc_status": "未见公开PoC",
    "research_value": "车载OS/多媒体/无钥匙系统供应链风险。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-8090",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-8090",
        "https://support.blackberry.com/pkb/s/article/141027",
        "https://cveawg.mitre.org/api/cve/CVE-2025-8090"
    ],
    "affected": [
        {
            "vendor": "BlackBerry Ltd",
            "product": "QNX Software Development Platform",
            "versions": [
                {
                    "version": "7.1 and 7.0",
                    "status": "affected",
                    "versionType": "custom"
                },
                {
                    "version": "cpe:2.3:a:blackberry:qnx_software_development_platform:7.1:*:*:*:*:*:*:*",
                    "status": "affected",
                    "versionType": "cpe"
                },
                {
                    "version": "cpe:2.3:a:blackberry:qnx_software_development_platform:7.0:*:*:*:*:*:*:*",
                    "status": "affected",
                    "versionType": "cpe"
                }
            ]
        },
        {
            "vendor": "BlackBerry Ltd",
            "product": "QNX OS for Safety",
            "versions": [
                {
                    "version": "2.2.7 and earlier",
                    "status": "affected",
                    "versionType": "custom"
                },
                {
                    "version": "cpe:2.3:o:blackberry:qnx_os_for_safety:2.2:7:*:*:*:*:*:*",
                    "status": "affected",
                    "versionType": "cpe"
                },
                {
                    "version": "2.1.4 and earlier",
                    "status": "affected",
                    "versionType": "custom"
                },
                {
                    "version": "cpe:2.3:o:blackberry:qnx_os_for_safety:2.1:4:*:*:*:*:*:*",
                    "status": "affected",
                    "versionType": "cpe"
                },
                {
                    "version": "2.0.2 and earlier",
                    "status": "affected",
                    "versionType": "custom"
                },
                {
                    "version": "cpe:2.3:o:blackberry:qnx_os_for_safety:2.0:2:*:*:*:*:*:*",
                    "status": "affected",
                    "versionType": "cpe"
                }
            ]
        },
        {
            "vendor": "BlackBerry Ltd.",
            "product": "QNX OS for Medical",
            "versions": [
                {
                    "version": "2.0.1 and earlier",
                    "status": "affected",
                    "versionType": "custom"
                },
                {
                    "version": "cpe:2.3:o:blackberry:qnx_os_for_medical:2.0:1:*:*:*:*:*:*",
                    "status": "affected",
                    "versionType": "cpe"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-8090",
        "BlackBerry",
        "QNX",
        "SDP",
        "Neutrino",
        "Kernel",
        "DoS",
        "Null",
        "pointer",
        "dereference",
        "MsgRegisterEvent",
        "system",
        "call",
        "could",
        "allow",
        "local",
        "access",
        "code",
        "execution",
        "abilities",
        "crash",
        "kernel",
        "BlackBerry Ltd",
        "QNX Software Development Platform",
        "QNX OS for Safety",
        "QNX OS for Medical"
    ]
}


class Poc17CVE20258090NullDerefDoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-020'
    meta_poc_name = 'CVE-2025-8090 空指针引用/DoS Exposure Audit'
    meta_cve_id = 'CVE-2025-8090'
    meta_severity = 'Medium'
    meta_protocol = 'local'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-8090'
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

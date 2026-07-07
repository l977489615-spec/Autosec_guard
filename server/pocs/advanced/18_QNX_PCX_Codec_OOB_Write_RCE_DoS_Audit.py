#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 21,
    "cve": "CVE-2025-2474",
    "year": 2025,
    "domain": "IVI/OS/协议/隐私",
    "vendor_product": "BlackBerry QNX SDP",
    "component": "PCX image codec",
    "type": "越界写/RCE或DoS",
    "summary": "QNX SDP 8.0/7.1/7.0 PCX编解码器越界写，可DoS或代码执行。",
    "source_description": "Out-of-bounds write in the PCX image codec in QNX SDP versions 8.0, 7.1 and 7.0 could allow an unauthenticated attacker to cause a denial-of-service condition or execute code in the context of the process using the image codec.",
    "poc_status": "未见公开PoC；供应商公告",
    "research_value": "车载OS/多媒体/无钥匙系统供应链风险。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-2474",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-2474",
        "https://support.blackberry.com/pkb/s/article/140646",
        "https://cveawg.mitre.org/api/cve/CVE-2025-2474"
    ],
    "affected": [
        {
            "vendor": "BlackBerry",
            "product": "QNX Software Development Platform (SDP)",
            "versions": [
                {
                    "version": "8.0, 7.1 and 7.0",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-2474",
        "BlackBerry",
        "QNX",
        "SDP",
        "PCX",
        "image",
        "codec",
        "RCE",
        "DoS",
        "Out-of-bounds",
        "write",
        "could",
        "allow",
        "unauthenticated",
        "cause",
        "denial-of-service",
        "condition",
        "execute",
        "code",
        "context",
        "process",
        "using",
        "QNX Software Development Platform (SDP"
    ]
}


class Poc18CVE20252474OutOfBoundsRCEDoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-021'
    meta_poc_name = 'CVE-2025-2474 越界写/RCE或DoS Exposure Audit'
    meta_cve_id = 'CVE-2025-2474'
    meta_severity = 'Critical'
    meta_protocol = 'local'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-2474'
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

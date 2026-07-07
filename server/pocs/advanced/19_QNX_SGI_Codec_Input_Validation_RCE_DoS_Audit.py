#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 28,
    "cve": "CVE-2024-35213",
    "year": 2024,
    "domain": "车载OS/QNX",
    "vendor_product": "BlackBerry QNX SDP",
    "component": "SGI image codec",
    "type": "输入校验/RCE或DoS",
    "summary": "QNX SDP 6.6/7.0/7.1 SGI图像编解码器输入校验不当，可DoS或代码执行。",
    "source_description": "An improper input validation vulnerability in the SGI Image Codec of QNX SDP version(s) 6.6, 7.0, and 7.1 could allow an attacker to potentially cause a denial-of-service condition or execute code in the context of the image processing process.",
    "poc_status": "未见公开PoC；供应商公告",
    "research_value": "QNX广泛用于IVI、ADAS和域控制器，属于车载基础软件风险。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-35213",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-35213",
        "https://support.blackberry.com/pkb/s/article/139914",
        "https://cveawg.mitre.org/api/cve/CVE-2024-35213"
    ],
    "affected": [
        {
            "vendor": "BlackBerry",
            "product": "QNX Software Development Platform (SDP)",
            "versions": [
                {
                    "version": "6.6.0",
                    "status": "affected",
                    "lessThanOrEqual": "7.1",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-35213",
        "BlackBerry",
        "QNX",
        "SDP",
        "SGI",
        "image",
        "codec",
        "RCE",
        "DoS",
        "improper",
        "input",
        "validation",
        "vulnerability",
        "Image",
        "Codec",
        "could",
        "allow",
        "potentially",
        "cause",
        "denial-of-service",
        "condition",
        "execute",
        "code",
        "context",
        "processing",
        "process",
        "QNX Software Development Platform (SDP"
    ]
}


class Poc19CVE202435213RCEDoSInputValidationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-028'
    meta_poc_name = 'CVE-2024-35213 输入校验/RCE或DoS Exposure Audit'
    meta_cve_id = 'CVE-2024-35213'
    meta_severity = 'High'
    meta_protocol = 'local'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-35213'
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

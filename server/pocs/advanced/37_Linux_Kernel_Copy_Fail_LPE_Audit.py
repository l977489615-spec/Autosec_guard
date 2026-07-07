#!/usr/bin/env python3
"""Safe exposure audit for Linux Copy Fail local privilege escalation risk."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": "POC-LAB-009",
    "cve": "CVE-2026-31431",
    "year": 2026,
    "domain": "车载Linux/边缘节点",
    "vendor_product": "Linux kernel",
    "component": "AF_ALG / algif_aead / splice page cache handling",
    "type": "本地权限提升/容器逃逸",
    "summary": "Linux Copy Fail 漏洞影响启用 CRYPTO_USER_API_AEAD 的内核，本地低权限用户可能提权；车载 Linux、边缘网关、测试台架和容器化诊断节点需排查。",
    "source_description": "poc-lab documents Copy Fail, a Linux kernel local privilege escalation involving splice and AF_ALG AEAD in-place handling.",
    "poc_status": "poc-lab公开复现；本插件仅做安全暴露审计",
    "research_value": "车载 Linux 与边缘节点常启用通用发行版内核和容器，LPE/容器逃逸会放大其他入口漏洞。",
    "source_url": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-31431%20Copy%20Fail",
    "references": [
        "https://github.com/Unclecheng-li/poc-lab",
        "https://copy.fail",
    ],
    "affected": [
        {
            "vendor": "Linux",
            "product": "Linux kernel",
            "versions": [
                {"version": "4.14", "status": "affected", "lessThan": "5.10.254"},
                {"version": "5.11", "status": "affected", "lessThan": "5.15.204"},
                {"version": "5.16", "status": "affected", "lessThan": "6.1.170"},
                {"version": "6.2", "status": "affected", "lessThan": "6.6.137"},
                {"version": "6.7", "status": "affected", "lessThan": "6.12.85"},
                {"version": "6.13", "status": "affected", "lessThan": "6.18.22"},
            ],
        }
    ],
    "signature_tokens": [
        "CVE-2026-31431", "Copy Fail", "Linux", "kernel", "AF_ALG",
        "algif_aead", "CONFIG_CRYPTO_USER_API_AEAD", "splice", "a664bf3d603d",
        "container escape", "local privilege escalation",
    ],
}


class LinuxKernelCopyFailLPEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-ADV-037"
    meta_poc_name = "Linux Kernel Copy Fail LPE Audit"
    meta_cve_id = "CVE-2026-31431"
    meta_severity = "High"
    meta_protocol = "local"
    meta_target_os = ["linux"]
    meta_required_params = ["software_inventory_text"]
    meta_profiles = ["advanced", "kernel", "edge"]
    meta_source_url = VULN["source_url"]
    meta_attack_surface = "车载Linux/边缘节点"
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

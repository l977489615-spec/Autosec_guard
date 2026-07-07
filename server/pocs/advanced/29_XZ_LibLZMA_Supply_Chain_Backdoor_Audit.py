#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 94,
    "cve": "CVE-2024-3094",
    "year": 2024,
    "domain": "车载Linux供应链",
    "vendor_product": "xz utils",
    "component": "liblzma backdoor",
    "type": "供应链后门",
    "summary": "若车载Linux构建链/镜像引入受影响xz，存在供应链后门风险。",
    "source_description": "Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. \r\nThrough a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.",
    "poc_status": "有公开检测/分析PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
        "https://access.redhat.com/security/cve/CVE-2024-3094",
        "https://bugzilla.redhat.com/show_bug.cgi?id=2272210",
        "https://www.openwall.com/lists/oss-security/2024/03/29/4",
        "https://www.redhat.com/en/blog/urgent-security-alert-fedora-41-and-rawhide-users",
        "https://cveawg.mitre.org/api/cve/CVE-2024-3094"
    ],
    "affected": [
        {
            "vendor": "",
            "product": "",
            "versions": [
                {
                    "version": "5.6.0",
                    "status": "affected"
                },
                {
                    "version": "5.6.1",
                    "status": "affected"
                }
            ]
        },
        {
            "vendor": "Red Hat",
            "product": "Red Hat Enterprise Linux 10",
            "versions": []
        },
        {
            "vendor": "Red Hat",
            "product": "Red Hat Enterprise Linux 6",
            "versions": []
        },
        {
            "vendor": "Red Hat",
            "product": "Red Hat Enterprise Linux 7",
            "versions": []
        },
        {
            "vendor": "Red Hat",
            "product": "Red Hat Enterprise Linux 8",
            "versions": []
        },
        {
            "vendor": "Red Hat",
            "product": "Red Hat Enterprise Linux 9",
            "versions": []
        },
        {
            "vendor": "Red Hat",
            "product": "Red Hat JBoss Enterprise Application Platform 8",
            "versions": []
        }
    ],
    "signature_tokens": [
        "CVE-2024-3094",
        "utils",
        "liblzma",
        "backdoor",
        "Malicious",
        "code",
        "discovered",
        "upstream",
        "tarballs",
        "starting",
        "series",
        "complex",
        "obfuscations",
        "build",
        "process",
        "extracts",
        "prebuilt",
        "object",
        "file",
        "disguised",
        "test",
        "existing",
        "source",
        "which",
        "then",
        "used",
        "modify",
        "Red Hat",
        "Red Hat Enterprise Linux 10",
        "Red Hat Enterprise Linux 6"
    ]
}


class Poc29CVE20243094ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-094'
    meta_poc_name = 'CVE-2024-3094 供应链后门 Exposure Audit'
    meta_cve_id = 'CVE-2024-3094'
    meta_severity = 'Critical'
    meta_protocol = 'local'
    meta_target_os = ['linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-3094'
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 92,
    "cve": "CVE-2023-4863",
    "year": 2023,
    "domain": "IVI/浏览器/媒体",
    "vendor_product": "libwebp",
    "component": "WebP decoder",
    "type": "堆溢出/RCE",
    "summary": "车机浏览器/消息预览/媒体解析若使用libwebp可能受影响。",
    "source_description": "Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 and libwebp 1.3.2 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: Critical)",
    "poc_status": "有公开PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-4863",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-4863",
        "https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop_11.html",
        "https://crbug.com/1479274",
        "https://en.bandisoft.com/honeyview/history/",
        "https://stackdiary.com/critical-vulnerability-in-webp-codec-cve-2023-4863/",
        "https://www.mozilla.org/en-US/security/advisories/mfsa2023-40/",
        "https://github.com/webmproject/libwebp/commit/902bc9190331343b2017211debcec8d2ab87e17a",
        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4863",
        "https://security-tracker.debian.org/tracker/CVE-2023-4863",
        "https://bugzilla.suse.com/show_bug.cgi?id=1215231",
        "https://news.ycombinator.com/item?id=37478403",
        "https://cveawg.mitre.org/api/cve/CVE-2023-4863"
    ],
    "affected": [
        {
            "vendor": "Google",
            "product": "Chrome",
            "versions": [
                {
                    "version": "116.0.5845.187",
                    "status": "affected",
                    "lessThan": "116.0.5845.187",
                    "versionType": "custom"
                }
            ]
        },
        {
            "vendor": "Google",
            "product": "libwebp",
            "versions": [
                {
                    "version": "1.3.2",
                    "status": "affected",
                    "lessThan": "1.3.2",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2023-4863",
        "libwebp",
        "WebP",
        "decoder",
        "RCE",
        "Heap",
        "buffer",
        "overflow",
        "Google",
        "Chrome",
        "prior",
        "allowed",
        "remote",
        "perform",
        "bounds",
        "memory",
        "write",
        "crafted",
        "HTML",
        "page",
        "Chromium",
        "security",
        "severity",
        "Critical"
    ]
}


class Poc64CVE20234863RCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-092'
    meta_poc_name = 'CVE-2023-4863 堆溢出/RCE Exposure Audit'
    meta_cve_id = 'CVE-2023-4863'
    meta_severity = 'Critical'
    meta_protocol = 'http'
    meta_target_os = ['all']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['application']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-4863'
    meta_attack_surface = '车机APP/应用'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

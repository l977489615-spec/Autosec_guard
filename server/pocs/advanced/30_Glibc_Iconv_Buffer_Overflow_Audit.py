#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 100,
    "cve": "CVE-2024-2961",
    "year": 2024,
    "domain": "车载Linux依赖库",
    "vendor_product": "glibc iconv",
    "component": "ISO-2022-CN-EXT",
    "type": "缓冲区溢出",
    "summary": "车载Linux/IVI若使用glibc iconv解析文本可能受影响。",
    "source_description": "The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.",
    "poc_status": "有公开PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-2961",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-2961",
        "https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2024-0004",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/P3I4KYS6EU6S7QZ47WFNTPVAHFIUQNEL/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YAMJQI3Y6BHWV3CUTYBXOZONCUJNOB2Z/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BTJFBGHDYG5PEIFD5WSSSKSFZ2AZWC5N/",
        "http://www.openwall.com/lists/oss-security/2024/04/24/2",
        "http://www.openwall.com/lists/oss-security/2024/04/17/9",
        "http://www.openwall.com/lists/oss-security/2024/04/18/4",
        "https://lists.debian.org/debian-lts-announce/2024/05/msg00001.html",
        "http://www.openwall.com/lists/oss-security/2024/05/27/2",
        "http://www.openwall.com/lists/oss-security/2024/05/27/6",
        "https://cveawg.mitre.org/api/cve/CVE-2024-2961"
    ],
    "affected": [
        {
            "vendor": "The GNU C Library",
            "product": "glibc",
            "versions": [
                {
                    "version": "2.1.93",
                    "status": "affected",
                    "lessThan": "2.40",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-2961",
        "glibc",
        "iconv",
        "ISO-2022-CN-EXT",
        "function",
        "Library",
        "older",
        "overflow",
        "output",
        "buffer",
        "passed",
        "bytes",
        "when",
        "converting",
        "strings",
        "character",
        "which",
        "used",
        "crash",
        "application",
        "overwrite",
        "neighbouring",
        "variable",
        "The GNU C Library"
    ]
}


class Poc30CVE20242961ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-100'
    meta_poc_name = 'CVE-2024-2961 缓冲区溢出 Exposure Audit'
    meta_cve_id = 'CVE-2024-2961'
    meta_severity = 'High'
    meta_protocol = 'local'
    meta_target_os = ['linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-2961'
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

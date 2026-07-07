#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 90,
    "cve": "CVE-2022-37434",
    "year": 2022,
    "domain": "车载OS依赖库",
    "vendor_product": "zlib/libpng stacks",
    "component": "inflate",
    "type": "整数溢出/内存破坏",
    "summary": "常见压缩库漏洞，车机媒体/OTA包解析可能间接受影响。",
    "source_description": "zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in inflate in inflate.c via a large gzip header extra field. NOTE: only applications that call inflateGetHeader are affected. Some common applications bundle the affected zlib source code but may be unable to call inflateGetHeader (e.g., see the nodejs/node reference).",
    "poc_status": "有公开PoC/检测脚本",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-37434",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2022-37434",
        "https://github.com/ivd38/zlib_overflow",
        "https://github.com/madler/zlib/commit/eff308af425b67093bab25f80f1ae950166bece1",
        "https://github.com/madler/zlib/blob/21767c654d31d2dccdde4330529775c6c5fd5389/zlib.h#L1062-L1063",
        "https://github.com/nodejs/node/blob/75b68c6e4db515f76df73af476eccf382bbcb00a/deps/zlib/inflate.c#L762-L764",
        "http://www.openwall.com/lists/oss-security/2022/08/05/2",
        "https://github.com/curl/curl/issues/9271",
        "http://www.openwall.com/lists/oss-security/2022/08/09/1",
        "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YRQAI7H4M4RQZ2IWZUEEXECBE5D56BH2/",
        "https://www.debian.org/security/2022/dsa-5218",
        "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NMBOJ77A7T7PQCARMDUK75TE6LLESZ3O/",
        "https://cveawg.mitre.org/api/cve/CVE-2022-37434"
    ],
    "affected": [
        {
            "vendor": "n/a",
            "product": "n/a",
            "versions": [
                {
                    "version": "n/a",
                    "status": "unknown"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2022-37434",
        "zlib",
        "libpng",
        "stacks",
        "inflate",
        "heap-based",
        "buffer",
        "over-read",
        "overflow",
        "inflate.c",
        "large",
        "gzip",
        "header",
        "extra",
        "field",
        "NOTE",
        "only",
        "applications",
        "call",
        "inflateGetHeader",
        "Some",
        "common",
        "bundle",
        "source",
        "code",
        "unable"
    ]
}


class Poc55CVE202237434ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-090'
    meta_poc_name = 'CVE-2022-37434 整数溢出/内存破坏 Exposure Audit'
    meta_cve_id = 'CVE-2022-37434'
    meta_severity = 'High'
    meta_protocol = 'https'
    meta_target_os = ['linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2022-37434'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

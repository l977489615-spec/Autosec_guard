#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 97,
    "cve": "CVE-2024-4741",
    "year": 2024,
    "domain": "车载OS/QNX依赖库",
    "vendor_product": "OpenSSL on QNX",
    "component": "TLS handshake",
    "type": "内存使用/DoS",
    "summary": "OpenSSL握手路径漏洞，影响联网车载服务。",
    "source_description": "Issue summary: Calling the OpenSSL API function SSL_free_buffers may cause\nmemory to be accessed that was previously freed in some situations\n\nImpact summary: A use after free can have a range of potential consequences such\nas the corruption of valid data, crashes or execution of arbitrary code.\nHowever, only applications that directly call the SSL_free_buffers function are\naffected by this issue. Applications that do not call this function are not\nvulnerable. Our investigations indicate that this function is rarely used by\napplications.\n\nThe SSL_free_buffers function is used to free the internal OpenSSL buffer used\nwhen processing an incoming record from the network. The call is only expected\nto succeed if the buffer is not currently in use. However, two scenarios have\nbeen identified where the buffer is freed even when still in use.\n\nThe first scenario occurs where a record header has been received from the\nnetwork and processed by OpenSSL, but the full record body has not yet arrived.\nIn this case calling SSL_free_buffers will succeed even though a record has only\nbeen partially processed and the buffer is still in use.\n\nThe second scenario occurs where a full record containing application data has\nbeen received and processed by OpenSSL but the application has only read part of\nthis data. Again a call to SSL_free_buffers will succeed even though the buffer\nis still in use.\n\nWhile these scenarios could occur accidentally during normal operation a\nmalicious attacker could attempt to engineer a stituation where this occurs.\nWe are not aware of this issue being actively exploited.\n\nThe FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.",
    "poc_status": "有公开公告",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-4741",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-4741",
        "https://www.openssl.org/news/secadv/20240528.txt",
        "https://github.com/openssl/openssl/commit/e5093133c35ca82874ad83697af76f4b0f7e3bd8",
        "https://github.com/openssl/openssl/commit/c88c3de51020c37e8706bf7a682a162593053aac",
        "https://github.com/openssl/openssl/commit/704f725b96aa373ee45ecfb23f6abfe8be8d9177",
        "https://github.com/openssl/openssl/commit/b3f0eb0a295f58f16ba43ba99dad70d4ee5c437d",
        "https://github.openssl.org/openssl/extended-releases/commit/f7a045f3143fc6da2ee66bf52d8df04829590dd4",
        "https://cveawg.mitre.org/api/cve/CVE-2024-4741"
    ],
    "affected": [
        {
            "vendor": "OpenSSL",
            "product": "OpenSSL",
            "versions": [
                {
                    "version": "3.3.0",
                    "status": "affected",
                    "lessThan": "3.3.1",
                    "versionType": "semver"
                },
                {
                    "version": "3.2.0",
                    "status": "affected",
                    "lessThan": "3.2.2",
                    "versionType": "semver"
                },
                {
                    "version": "3.1.0",
                    "status": "affected",
                    "lessThan": "3.1.6",
                    "versionType": "semver"
                },
                {
                    "version": "3.0.0",
                    "status": "affected",
                    "lessThan": "3.0.14",
                    "versionType": "semver"
                },
                {
                    "version": "1.1.1",
                    "status": "affected",
                    "lessThan": "1.1.1y",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-4741",
        "OpenSSL",
        "QNX",
        "TLS",
        "handshake",
        "DoS",
        "Issue",
        "summary",
        "Calling",
        "function",
        "SSL_free_buffers",
        "cause",
        "memory",
        "accessed",
        "previously",
        "freed",
        "some",
        "situations",
        "Impact",
        "free",
        "have",
        "range",
        "potential",
        "consequences",
        "such",
        "corruption",
        "valid",
        "data",
        "crashes",
        "execution"
    ]
}


class Poc59CVE20244741DoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-097'
    meta_poc_name = 'CVE-2024-4741 内存使用/DoS Exposure Audit'
    meta_cve_id = 'CVE-2024-4741'
    meta_severity = 'Medium'
    meta_protocol = 'tls'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-4741'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

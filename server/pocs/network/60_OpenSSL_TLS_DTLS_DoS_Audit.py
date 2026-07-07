#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 98,
    "cve": "CVE-2024-2511",
    "year": 2024,
    "domain": "车载OS/QNX依赖库",
    "vendor_product": "OpenSSL on QNX",
    "component": "TLS/DTLS",
    "type": "DoS",
    "summary": "OpenSSL TLS/DTLS相关DoS，车载基础镜像需修复。",
    "source_description": "Issue summary: Some non-default TLS server configurations can cause unbounded\nmemory growth when processing TLSv1.3 sessions\n\nImpact summary: An attacker may exploit certain server configurations to trigger\nunbounded memory growth that would lead to a Denial of Service\n\nThis problem can occur in TLSv1.3 if the non-default SSL_OP_NO_TICKET option is\nbeing used (but not if early_data support is also configured and the default\nanti-replay protection is in use). In this case, under certain conditions, the\nsession cache can get into an incorrect state and it will fail to flush properly\nas it fills. The session cache will continue to grow in an unbounded manner. A\nmalicious client could deliberately create the scenario for this failure to\nforce a Denial of Service. It may also happen by accident in normal operation.\n\nThis issue only affects TLS servers supporting TLSv1.3. It does not affect TLS\nclients.\n\nThe FIPS modules in 3.2, 3.1 and 3.0 are not affected by this issue. OpenSSL\n1.0.2 is also not affected by this issue.",
    "poc_status": "有公开公告",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-2511",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-2511",
        "https://www.openssl.org/news/secadv/20240408.txt",
        "https://github.com/openssl/openssl/commit/e9d7083e241670332e0443da0f0d4ffb52829f08",
        "https://github.com/openssl/openssl/commit/7e4d731b1c07201ad9374c1cd9ac5263bdf35bce",
        "https://github.com/openssl/openssl/commit/b52867a9f618bb955bed2a3ce3db4d4f97ed8e5d",
        "https://github.openssl.org/openssl/extended-releases/commit/5f8d25770ae6437db119dfc951e207271a326640",
        "https://cveawg.mitre.org/api/cve/CVE-2024-2511"
    ],
    "affected": [
        {
            "vendor": "OpenSSL",
            "product": "OpenSSL",
            "versions": [
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
        "CVE-2024-2511",
        "OpenSSL",
        "QNX",
        "TLS",
        "DTLS",
        "DoS",
        "Issue",
        "summary",
        "Some",
        "non-default",
        "server",
        "configurations",
        "cause",
        "unbounded",
        "memory",
        "growth",
        "when",
        "processing",
        "TLSv1.3",
        "sessions",
        "Impact",
        "exploit",
        "certain",
        "trigger",
        "would",
        "lead",
        "Denial",
        "Service"
    ]
}


class Poc60CVE20242511DoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-098'
    meta_poc_name = 'CVE-2024-2511 DoS Exposure Audit'
    meta_cve_id = 'CVE-2024-2511'
    meta_severity = 'Medium'
    meta_protocol = 'tls'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-2511'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

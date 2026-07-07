#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 95,
    "cve": "CVE-2024-6119",
    "year": 2024,
    "domain": "车载OS/QNX依赖库",
    "vendor_product": "OpenSSL on QNX",
    "component": "X.509 name checks",
    "type": "DoS/验证问题",
    "summary": "QNX平台OpenSSL漏洞集合中的一项，影响证书处理。",
    "source_description": "Issue summary: Applications performing certificate name checks (e.g., TLS\nclients checking server certificates) may attempt to read an invalid memory\naddress resulting in abnormal termination of the application process.\n\nImpact summary: Abnormal termination of an application can a cause a denial of\nservice.\n\nApplications performing certificate name checks (e.g., TLS clients checking\nserver certificates) may attempt to read an invalid memory address when\ncomparing the expected name with an `otherName` subject alternative name of an\nX.509 certificate. This may result in an exception that terminates the\napplication program.\n\nNote that basic certificate chain validation (signatures, dates, ...) is not\naffected, the denial of service can occur only when the application also\nspecifies an expected DNS name, Email address or IP address.\n\nTLS servers rarely solicit client certificates, and even when they do, they\ngenerally don't perform a name check against a reference identifier (expected\nidentity), but rather extract the presented identity after checking the\ncertificate chain.  So TLS servers are generally not affected and the severity\nof the issue is Moderate.\n\nThe FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.",
    "poc_status": "有公开公告",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6119",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-6119",
        "https://openssl-library.org/news/secadv/20240903.txt",
        "https://github.com/openssl/openssl/commit/7dfcee2cd2a63b2c64b9b4b0850be64cb695b0a0",
        "https://github.com/openssl/openssl/commit/05f360d9e849a1b277db628f1f13083a7f8dd04f",
        "https://github.com/openssl/openssl/commit/621f3729831b05ee828a3203eddb621d014ff2b2",
        "https://github.com/openssl/openssl/commit/06d1dc3fa96a2ba5a3e22735a033012aadc9f0d6",
        "https://cveawg.mitre.org/api/cve/CVE-2024-6119"
    ],
    "affected": [
        {
            "vendor": "OpenSSL",
            "product": "OpenSSL",
            "versions": [
                {
                    "version": "3.3.0",
                    "status": "affected",
                    "lessThan": "3.3.2",
                    "versionType": "semver"
                },
                {
                    "version": "3.2.0",
                    "status": "affected",
                    "lessThan": "3.2.3",
                    "versionType": "semver"
                },
                {
                    "version": "3.1.0",
                    "status": "affected",
                    "lessThan": "3.1.7",
                    "versionType": "semver"
                },
                {
                    "version": "3.0.0",
                    "status": "affected",
                    "lessThan": "3.0.15",
                    "versionType": "semver"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-6119",
        "OpenSSL",
        "QNX",
        "X.509",
        "name",
        "checks",
        "DoS",
        "Issue",
        "summary",
        "Applications",
        "performing",
        "certificate",
        "e.g",
        "clients",
        "checking",
        "server",
        "certificates",
        "attempt",
        "read",
        "invalid",
        "memory",
        "address",
        "resulting",
        "abnormal",
        "termination",
        "application",
        "process",
        "Impact",
        "Abnormal",
        "cause"
    ]
}


class Poc57CVE20246119DoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-095'
    meta_poc_name = 'CVE-2024-6119 DoS/验证问题 Exposure Audit'
    meta_cve_id = 'CVE-2024-6119'
    meta_severity = 'High'
    meta_protocol = 'tls'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-6119'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

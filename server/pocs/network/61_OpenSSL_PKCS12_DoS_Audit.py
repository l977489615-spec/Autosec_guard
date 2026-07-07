#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 99,
    "cve": "CVE-2024-0727",
    "year": 2024,
    "domain": "车载OS/QNX依赖库",
    "vendor_product": "OpenSSL on QNX",
    "component": "PKCS12",
    "type": "DoS",
    "summary": "OpenSSL PKCS12解析DoS，可能影响证书导入/OTA流程。",
    "source_description": "Issue summary: Processing a maliciously formatted PKCS12 file may lead OpenSSL\nto crash leading to a potential Denial of Service attack\n\nImpact summary: Applications loading files in the PKCS12 format from untrusted\nsources might terminate abruptly.\n\nA file in PKCS12 format can contain certificates and keys and may come from an\nuntrusted source. The PKCS12 specification allows certain fields to be NULL, but\nOpenSSL does not correctly check for this case. This can lead to a NULL pointer\ndereference that results in OpenSSL crashing. If an application processes PKCS12\nfiles from an untrusted source using the OpenSSL APIs then that application will\nbe vulnerable to this issue.\n\nOpenSSL APIs that are vulnerable to this are: PKCS12_parse(),\nPKCS12_unpack_p7data(), PKCS12_unpack_p7encdata(), PKCS12_unpack_authsafes()\nand PKCS12_newpass().\n\nWe have also fixed a similar issue in SMIME_write_PKCS7(). However since this\nfunction is related to writing data we do not consider it security significant.\n\nThe FIPS modules in 3.2, 3.1 and 3.0 are not affected by this issue.",
    "poc_status": "有公开公告",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0727",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-0727",
        "https://www.openssl.org/news/secadv/20240125.txt",
        "https://github.com/openssl/openssl/commit/775acfdbd0c6af9ac855f34969cdab0c0c90844a",
        "https://github.com/openssl/openssl/commit/d135eeab8a5dbf72b3da5240bab9ddb7678dbd2c",
        "https://github.com/openssl/openssl/commit/09df4395b5071217b76dc7d3d2e630eb8c5a79c2",
        "https://github.openssl.org/openssl/extended-releases/commit/03b3941d60c4bce58fab69a0c22377ab439bc0e8",
        "https://github.openssl.org/openssl/extended-releases/commit/aebaa5883e31122b404e450732dc833dc9dee539",
        "https://cveawg.mitre.org/api/cve/CVE-2024-0727"
    ],
    "affected": [
        {
            "vendor": "OpenSSL",
            "product": "OpenSSL",
            "versions": [
                {
                    "version": "3.2.0",
                    "status": "affected",
                    "lessThan": "3.2.1",
                    "versionType": "semver"
                },
                {
                    "version": "3.1.0",
                    "status": "affected",
                    "lessThan": "3.1.5",
                    "versionType": "semver"
                },
                {
                    "version": "3.0.0",
                    "status": "affected",
                    "lessThan": "3.0.13",
                    "versionType": "semver"
                },
                {
                    "version": "1.1.1",
                    "status": "affected",
                    "lessThan": "1.1.1x",
                    "versionType": "custom"
                },
                {
                    "version": "1.0.2",
                    "status": "affected",
                    "lessThan": "1.0.2zj",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-0727",
        "OpenSSL",
        "QNX",
        "PKCS12",
        "DoS",
        "Issue",
        "summary",
        "Processing",
        "maliciously",
        "formatted",
        "file",
        "lead",
        "crash",
        "leading",
        "potential",
        "Denial",
        "Service",
        "attack",
        "Impact",
        "Applications",
        "loading",
        "files",
        "format",
        "untrusted",
        "sources",
        "might",
        "terminate",
        "abruptly"
    ]
}


class Poc61CVE20240727DoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-099'
    meta_poc_name = 'CVE-2024-0727 DoS Exposure Audit'
    meta_cve_id = 'CVE-2024-0727'
    meta_severity = 'Medium'
    meta_protocol = 'https'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-0727'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

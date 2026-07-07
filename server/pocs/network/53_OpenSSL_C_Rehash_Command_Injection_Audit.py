#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 88,
    "cve": "CVE-2022-1292",
    "year": 2022,
    "domain": "车载OS/QNX依赖库",
    "vendor_product": "OpenSSL on QNX",
    "component": "c_rehash script",
    "type": "命令注入",
    "summary": "QNX发行组件OpenSSL漏洞，影响车载基础镜像依赖。",
    "source_description": "The c_rehash script does not properly sanitise shell metacharacters to prevent command injection. This script is distributed by some operating systems in a manner where it is automatically executed. On such operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool. Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2). Fixed in OpenSSL 1.1.1o (Affected 1.1.1-1.1.1n). Fixed in OpenSSL 1.0.2ze (Affected 1.0.2-1.0.2zd).",
    "poc_status": "有公开PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-1292",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2022-1292",
        "https://www.openssl.org/news/secadv/20220503.txt",
        "https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=1ad73b4d27bd8c1b369a3cd453681d3a4f1bb9b2",
        "https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=e5fd1728ef4c7a5bf7c7a7163ca60370460a6e23",
        "https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=548d3f280a6e737673f5b61fce24bb100108dfeb",
        "https://lists.debian.org/debian-lts-announce/2022/05/msg00019.html",
        "https://www.debian.org/security/2022/dsa-5139",
        "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VX4KWHPMKYJL6ZLW4M5IU7E5UV5ZWJQU/",
        "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZNU5M7BXMML26G3GPYKFGQYPQDRSNKDD/",
        "https://www.oracle.com/security-alerts/cpujul2022.html",
        "https://security.netapp.com/advisory/ntap-20220602-0009/",
        "https://cveawg.mitre.org/api/cve/CVE-2022-1292"
    ],
    "affected": [
        {
            "vendor": "OpenSSL",
            "product": "OpenSSL",
            "versions": [
                {
                    "version": "Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2)",
                    "status": "affected"
                },
                {
                    "version": "Fixed in OpenSSL 1.1.1o (Affected 1.1.1-1.1.1n)",
                    "status": "affected"
                },
                {
                    "version": "Fixed in OpenSSL 1.0.2ze (Affected 1.0.2-1.0.2zd)",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2022-1292",
        "OpenSSL",
        "QNX",
        "c_rehash",
        "script",
        "does",
        "properly",
        "sanitise",
        "shell",
        "metacharacters",
        "prevent",
        "command",
        "injection",
        "distributed",
        "some",
        "operating",
        "systems",
        "manner",
        "where",
        "automatically",
        "executed",
        "such",
        "could",
        "execute",
        "arbitrary",
        "commands",
        "privileges"
    ]
}


class Poc53CVE20221292InjectionAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-088'
    meta_poc_name = 'CVE-2022-1292 命令注入 Exposure Audit'
    meta_cve_id = 'CVE-2022-1292'
    meta_severity = 'High'
    meta_protocol = 'tls'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2022-1292'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

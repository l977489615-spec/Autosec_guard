#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 89,
    "cve": "CVE-2022-2068",
    "year": 2022,
    "domain": "车载OS/QNX依赖库",
    "vendor_product": "OpenSSL on QNX",
    "component": "AES OCB",
    "type": "数据加密实现错误",
    "summary": "OpenSSL OCB模式漏洞，车载Linux/QNX依赖库需排查。",
    "source_description": "In addition to the c_rehash shell command injection identified in CVE-2022-1292, further circumstances where the c_rehash script does not properly sanitise shell metacharacters to prevent command injection were found by code review. When the CVE-2022-1292 was fixed it was not discovered that there are other places in the script where the file names of certificates being hashed were possibly passed to a command executed through the shell. This script is distributed by some operating systems in a manner where it is automatically executed. On such operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool. Fixed in OpenSSL 3.0.4 (Affected 3.0.0,3.0.1,3.0.2,3.0.3). Fixed in OpenSSL 1.1.1p (Affected 1.1.1-1.1.1o). Fixed in OpenSSL 1.0.2zf (Affected 1.0.2-1.0.2ze).",
    "poc_status": "有公开细节",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-2068",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2022-2068",
        "https://www.openssl.org/news/secadv/20220621.txt",
        "https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=2c9c35870601b4a44d86ddbf512b38df38285cfa",
        "https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=9639817dac8bbbaa64d09efad7464ccc405527c7",
        "https://git.openssl.org/gitweb/?p=openssl.git%3Ba=commitdiff%3Bh=7a9c027159fe9e1bbc2cd38a8a2914bff0d5abd9",
        "https://www.debian.org/security/2022/dsa-5169",
        "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6WZZBKUHQFGSKGNXXKICSRPL7AMVW5M5/",
        "https://security.netapp.com/advisory/ntap-20220707-0008/",
        "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VCMNWKERPBKOEBNL7CLTTX3ZZCZLH7XA/",
        "https://cert-portal.siemens.com/productcert/pdf/ssa-332410.pdf",
        "https://cveawg.mitre.org/api/cve/CVE-2022-2068"
    ],
    "affected": [
        {
            "vendor": "OpenSSL",
            "product": "OpenSSL",
            "versions": [
                {
                    "version": "Fixed in OpenSSL 3.0.4 (Affected 3.0.0,3.0.1,3.0.2,3.0.3)",
                    "status": "affected"
                },
                {
                    "version": "Fixed in OpenSSL 1.1.1p (Affected 1.1.1-1.1.1o)",
                    "status": "affected"
                },
                {
                    "version": "Fixed in OpenSSL 1.0.2zf (Affected 1.0.2-1.0.2ze)",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2022-2068",
        "OpenSSL",
        "QNX",
        "AES",
        "OCB",
        "addition",
        "c_rehash",
        "shell",
        "command",
        "injection",
        "identified",
        "CVE-2022-1292",
        "further",
        "circumstances",
        "where",
        "script",
        "does",
        "properly",
        "sanitise",
        "metacharacters",
        "prevent",
        "were",
        "found",
        "code",
        "review",
        "When",
        "fixed",
        "discovered",
        "there"
    ]
}


class Poc54CVE20222068CryptoAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-089'
    meta_poc_name = 'CVE-2022-2068 数据加密实现错误 Exposure Audit'
    meta_cve_id = 'CVE-2022-2068'
    meta_severity = 'Medium'
    meta_protocol = 'tls'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2022-2068'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

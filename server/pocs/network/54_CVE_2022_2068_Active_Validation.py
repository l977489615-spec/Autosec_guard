#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin
from probe_utils import (
    tls_get_server_info, detect_openssl_version,
    openssl_version_affected, detection_confidence,
    score_probe_result, service_open, HTTPProbe,
)


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
                {"version": "3.0.0", "status": "affected", "lessThan": "3.0.4", "versionType": "semver"},
                {"version": "1.1.1", "status": "affected", "lessThan": "1.1.1p", "versionType": "custom"},
                {"version": "1.0.2", "status": "affected", "lessThan": "1.0.2zf", "versionType": "custom"},
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


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 443))
    cve = "CVE-2022-2068"

    evidence = {
        "cve": cve,
        "target": f"{target_ip}:{port}",
        "technique": "TLS fingerprinting + semantic version comparison + c_rehash CGI probe",
        "reference": "https://www.openssl.org/news/secadv/20220621.txt",
    }

    if not service_open(target_ip, port):
        evidence["service_open"] = False
        return {
            "vulnerable": None,
            "evidence": evidence,
            "detection_confidence": detection_confidence("E", evidence, "no_service"),
            "requires_manual_review": True,
        }
    evidence["service_open"] = True

    # Step 1: TLS fingerprinting
    tls_info = tls_get_server_info(target_ip, port)
    evidence.update({k: v for k, v in tls_info.items() if v})

    # Step 2: Try to get OpenSSL version
    detected_version = detect_openssl_version(target_ip, port)
    evidence["detected_openssl_version"] = detected_version

    # Step 3: HTTP probe for c_rehash CGI exposure (additional attack surface check)
    for http_port in (80, 443, port):
        try:
            use_tls = (http_port == 443)
            probe = HTTPProbe(target_ip, http_port, tls=use_tls, timeout=5)
            r = probe.get("/cgi-bin/c_rehash")
            if r.get("status") is not None:
                evidence["c_rehash_http_status"] = r.get("status")
                if r.get("status") not in (404, None):
                    evidence["c_rehash_endpoint_exists"] = True
            break
        except Exception:
            pass

    # Step 4: Version comparison
    if detected_version:
        affected = openssl_version_affected(detected_version, cve)
        evidence["version_in_affected_range"] = affected
        evidence["detection_level"] = "C"

        if affected is True:
            vulnerable = True
            conf = detection_confidence("C", evidence, "tls_fingerprint+version_range")
        elif affected is False:
            vulnerable = False
            conf = detection_confidence("C", evidence, "tls_fingerprint+version_range")
        else:
            vulnerable = None
            conf = detection_confidence("E", evidence, "tls_fingerprint_only")
    else:
        evidence["version_detection"] = "failed - version not visible in TLS/HTTP"
        evidence["detail"] = (
            f"OpenSSL version not detectable from TLS handshake. "
            f"TLS info: version={tls_info.get('tls_version')}, "
            f"server={tls_info.get('server_header', 'none')}. "
            f"Manual check: openssl s_client -connect {target_ip}:{port} 2>&1 | grep 'Server version'"
        )
        vulnerable = None
        conf = detection_confidence("E", evidence, "tls_fingerprint_only")

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "detection_confidence": conf,
        "requires_manual_review": vulnerable is None,
    }


class Poc54CVE20222068CryptoAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-054"
    meta_poc_name = 'CVE-2022-2068 数据加密实现错误 Active Validation'
    meta_cve_id = 'CVE-2022-2068'
    meta_severity = 'Medium'
    meta_protocol = 'tls'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2022-2068'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2022-2068']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "54_OpenSSL_AES_OCB_Crypto_Implementation_Audit") if "VULN" in dir() else "54_OpenSSL_AES_OCB_Crypto_Implementation_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc54CVE20222068CryptoAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

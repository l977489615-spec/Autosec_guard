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
                {"version": "3.0.0", "status": "affected", "lessThan": "3.0.3", "versionType": "semver"},
                {"version": "1.1.1", "status": "affected", "lessThan": "1.1.1o", "versionType": "custom"},
                {"version": "1.0.2", "status": "affected", "lessThan": "1.0.2ze", "versionType": "custom"},
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


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 443))
    cve = "CVE-2022-1292"

    evidence = {
        "cve": cve,
        "target": f"{target_ip}:{port}",
        "technique": "TLS fingerprinting + semantic version comparison + c_rehash HTTP probe",
        "reference": "https://www.openssl.org/news/secadv/20220503.txt",
    }

    if not service_open(target_ip, port):
        evidence["service_open"] = False
        # Also check HTTP port 80 for c_rehash CGI exposure
        http_port = 80
        if not service_open(target_ip, http_port):
            return {
                "vulnerable": None,
                "evidence": evidence,
                "detection_confidence": detection_confidence("E", evidence, "no_service"),
                "requires_manual_review": True,
            }
        port = http_port
    evidence["service_open"] = True

    # Step 1: TLS fingerprinting
    tls_info = tls_get_server_info(target_ip, port)
    evidence.update({k: v for k, v in tls_info.items() if v})

    # Step 2: Try to get OpenSSL version
    detected_version = detect_openssl_version(target_ip, port)
    evidence["detected_openssl_version"] = detected_version

    # Step 3: HTTP probe for c_rehash CGI exposure
    for http_port in (80, 443, port):
        try:
            use_tls = (http_port == 443)
            probe = HTTPProbe(target_ip, http_port, tls=use_tls, timeout=5)
            r = probe.get("/cgi-bin/c_rehash")
            if r.get("status") is not None:
                evidence["c_rehash_http_status"] = r.get("status")
                evidence["c_rehash_probe_port"] = http_port
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


class Poc53CVE20221292InjectionAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-088'
    meta_poc_name = 'CVE-2022-1292 命令注入 Active Validation'
    meta_cve_id = 'CVE-2022-1292'
    meta_severity = 'High'
    meta_protocol = 'tls'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2022-1292'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2022-1292']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "53_OpenSSL_C_Rehash_Command_Injection_Audit") if "VULN" in dir() else "53_OpenSSL_C_Rehash_Command_Injection_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc53CVE20221292InjectionAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

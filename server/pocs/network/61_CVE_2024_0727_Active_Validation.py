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
                {"version": "3.2.0", "status": "affected", "lessThan": "3.2.1", "versionType": "semver"},
                {"version": "3.1.0", "status": "affected", "lessThan": "3.1.5", "versionType": "semver"},
                {"version": "3.0.0", "status": "affected", "lessThan": "3.0.13", "versionType": "semver"},
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


def _probe_pkcs12_upload_endpoint(host: str, port: int) -> dict:
    """Check for web interfaces that accept PKCS12 file uploads."""
    result = {}
    pkcs12_paths = [
        "/upload",
        "/cert/upload",
        "/api/certificate",
        "/admin/cert",
        "/management/certificate",
        "/config/cert",
    ]
    for use_tls in (True, False):
        if use_tls and port not in (443, 8443):
            continue
        try:
            probe = HTTPProbe(host, port, tls=use_tls, timeout=5)
            for path in pkcs12_paths:
                r = probe.get(path)
                status = r.get("status")
                if status is not None and status not in (404, 500, None):
                    result["pkcs12_upload_endpoint"] = path
                    result["pkcs12_endpoint_status"] = status
                    body = r.get("body_text", "")
                    if any(k in body.lower() for k in ("pkcs12", "p12", "pfx", "certificate", "cert upload")):
                        result["pkcs12_endpoint_confirmed"] = True
                    break
            break
        except Exception:
            continue
    return result


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 443))
    cve = "CVE-2024-0727"

    evidence = {
        "cve": cve,
        "target": f"{target_ip}:{port}",
        "technique": "TLS fingerprinting + PKCS12 endpoint probe + semantic version comparison",
        "reference": "https://www.openssl.org/news/secadv/20240125.txt",
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

    # Step 2: Check for PKCS12 upload endpoints (web interface exposure)
    pkcs12_probe = _probe_pkcs12_upload_endpoint(target_ip, port)
    evidence.update({k: v for k, v in pkcs12_probe.items() if v is not None})

    # Step 3: Try to get OpenSSL version
    detected_version = detect_openssl_version(target_ip, port)
    evidence["detected_openssl_version"] = detected_version

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


class Poc61CVE20240727DoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-099'
    meta_poc_name = 'CVE-2024-0727 DoS Active Validation'
    meta_cve_id = 'CVE-2024-0727'
    meta_severity = 'Medium'
    meta_protocol = 'https'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-0727'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-0727']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "61_OpenSSL_PKCS12_DoS_Audit") if "VULN" in dir() else "61_OpenSSL_PKCS12_DoS_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc61CVE20240727DoSAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

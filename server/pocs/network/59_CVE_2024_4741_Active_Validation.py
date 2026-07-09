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
                {"version": "3.3.0", "status": "affected", "lessThan": "3.3.2", "versionType": "semver"},
                {"version": "3.2.0", "status": "affected", "lessThan": "3.2.3", "versionType": "semver"},
                {"version": "3.1.0", "status": "affected", "lessThan": "3.1.6", "versionType": "semver"},
                {"version": "3.0.0", "status": "affected", "lessThan": "3.0.14", "versionType": "semver"},
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


def _probe_tls_partial_record(host: str, port: int) -> dict:
    """Perform TLS handshake and observe server behavior with partial record.

    SSL_free_buffers UAF is hard to observe non-disruptively; we do a standard
    TLS handshake + partial HTTP request to exercise the buffer management path.
    """
    result = {}
    try:
        import ssl
        import socket
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=6) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                result["tls_version"] = tls_sock.version()
                result["cipher"] = tls_sock.cipher()
                result["tls_handshake_success"] = True
                # Send partial HTTP request (exercises SSL buffer path)
                tls_sock.send(b"GET / HTTP/1.0\r\n")
                try:
                    tls_sock.settimeout(2.0)
                    resp = tls_sock.recv(256)
                    result["partial_record_response_bytes"] = len(resp)
                except Exception:
                    pass
    except Exception as exc:
        result["tls_probe_error"] = str(exc)
    return result


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 443))
    cve = "CVE-2024-4741"

    evidence = {
        "cve": cve,
        "target": f"{target_ip}:{port}",
        "technique": "TLS fingerprinting + partial record handshake probe + semantic version comparison",
        "reference": "https://www.openssl.org/news/secadv/20240528.txt",
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

    # Step 2: Partial record probe (exercises SSL_free_buffers path)
    partial_result = _probe_tls_partial_record(target_ip, port)
    evidence.update({k: v for k, v in partial_result.items() if v is not None})

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


class Poc59CVE20244741DoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-097'
    meta_poc_name = 'CVE-2024-4741 DoS Active Validation'
    meta_cve_id = 'CVE-2024-4741'
    meta_severity = 'Medium'
    meta_protocol = 'tls'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-4741'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-4741']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "59_OpenSSL_TLS_Handshake_DoS_Audit") if "VULN" in dir() else "59_OpenSSL_TLS_Handshake_DoS_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc59CVE20244741DoSAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

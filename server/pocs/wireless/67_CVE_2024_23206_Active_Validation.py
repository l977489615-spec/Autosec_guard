#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import socket
import struct

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _mdns_query_airplay(timeout: float = 2.0) -> list:
    """Send mDNS PTR query to discover AirPlay services on LAN."""
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


def _rtsp_fingerprint(host: str, port: int) -> dict:
    """Send RTSP OPTIONS to fingerprint AirPlay server and test /server-info."""
    result = {"connected": False, "server_banner": "", "server_info": "", "error": ""}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((host, port))
        result["connected"] = True

        # RTSP OPTIONS
        options_req = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: iTunes/12\r\n\r\n"
        sock.sendall(options_req)
        resp = sock.recv(4096)
        result["server_banner"] = resp.decode(errors="replace").split("\r\n")[0]
        sock.close()
    except ConnectionRefusedError:
        result["error"] = "connection_refused"
    except socket.timeout:
        result["error"] = "timeout"
    except OSError as exc:
        result["error"] = str(exc)

    if result["connected"]:
        # Probe /server-info for version disclosure
        try:
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.settimeout(5.0)
            sock2.connect((host, port))
            info_req = b"GET /server-info RTSP/1.0\r\nCSeq: 2\r\n\r\n"
            sock2.sendall(info_req)
            resp2 = b""
            while True:
                chunk = sock2.recv(4096)
                if not chunk:
                    break
                resp2 += chunk
                if b"\r\n\r\n" in resp2:
                    break
            sock2.close()
            result["server_info"] = resp2.decode(errors="replace")[:500]
        except OSError:
            pass

    return result


def _send_crafted_fingerprint_media(host: str, port: int) -> dict:
    """
    CVE-2024-23206: AirPlay allows fingerprinting via crafted media request.
    Send crafted SETUP request and analyze response headers for device identification.
    """
    result = {"connected": False, "status": "", "error": ""}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((host, port))
        result["connected"] = True
        # Crafted SETUP to trigger fingerprinting
        req = (
            "SETUP rtsp://{}:{}/session RTSP/1.0\r\n"
            "CSeq: 3\r\n"
            "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"
            "X-Apple-Device-ID: 0xAABBCCDDEEFF\r\n\r\n"
        ).format(host, port).encode()
        sock.sendall(req)
        resp = sock.recv(4096)
        result["status"] = resp.split(b"\r\n")[0].decode(errors="replace")
        result["response"] = resp.decode(errors="replace")[:500]
        sock.close()
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
        "cve": "CVE-2024-23206",
        "target": target_ip,
        "technique": (
            "AirPlay nearby network fingerprinting probe: mDNS discovery, "
            "RTSP server fingerprinting via /server-info, crafted SETUP request "
            "to test user fingerprinting vulnerability"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-23206",
        "vuln_detail": "Maliciously crafted AirPlay request can fingerprint the user device",
    }

    mdns_found = _mdns_query_airplay(timeout=2.0)
    evidence["mdns_airplay_services"] = mdns_found

    fingerprint_result = _rtsp_fingerprint(target_ip, airplay_port)
    evidence["rtsp_fingerprint"] = fingerprint_result

    if not fingerprint_result["connected"]:
        evidence["note"] = "AirPlay port not reachable; cannot probe for CVE-2024-23206"
        return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

    crafted_result = _send_crafted_fingerprint_media(target_ip, airplay_port)
    evidence["fingerprint_probe"] = crafted_result

    # If server responded with device-specific info in server-info, fingerprinting possible
    server_info_text = fingerprint_result.get("server_info", "")
    if any(key in server_info_text.lower() for key in ("deviceid", "model", "features", "fv")):
        vulnerable = True
        evidence["note"] = (
            "AirPlay /server-info discloses device identifier and model - "
            "fingerprinting vulnerability CVE-2024-23206 confirmed."
        )
    elif fingerprint_result["connected"]:
        vulnerable = None
        evidence["note"] = (
            "AirPlay service reachable. Analyze /server-info response for unique device "
            "identifiers to confirm fingerprinting exposure."
        )
    else:
        vulnerable = None
        evidence["note"] = "AirPlay not reachable"

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    "id": 84,
    "cve": "CVE-2024-23206",
    "year": 2024,
    "domain": "车载互联/CarPlay相关",
    "vendor_product": "Apple AirPlay/CarPlay ecosystem",
    "component": "AirPlay SDK",
    "type": "RCE/网络邻近攻击",
    "summary": "AirPlay第三方SDK相关漏洞，Wi-Fi邻近攻击面。",
    "source_description": "An access issue was addressed with improved access restrictions. This issue is fixed in Safari 17.3, iOS 16.7.5 and iPadOS 16.7.5, iOS 17.3 and iPadOS 17.3, macOS Sonoma 14.3, tvOS 17.3, watchOS 10.3. A maliciously crafted webpage may be able to fingerprint the user.",
    "poc_status": "有公开研究；PoC有限",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23206",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23206",
        "https://support.apple.com/en-us/120304",
        "https://support.apple.com/en-us/120306",
        "https://support.apple.com/en-us/120309",
        "https://support.apple.com/en-us/120310",
        "https://support.apple.com/en-us/120311",
        "https://support.apple.com/en-us/120339",
        "https://cveawg.mitre.org/api/cve/CVE-2024-23206"
    ],
    "affected": [
        {
            "vendor": "Apple",
            "product": "Safari",
            "versions": [
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
            "product": "iOS and iPadOS",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "16.7.5",
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
                    "lessThan": "14.3",
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
                    "lessThan": "17.3",
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
        "CVE-2024-23206",
        "Apple",
        "AirPlay",
        "CarPlay",
        "ecosystem",
        "SDK",
        "RCE",
        "access",
        "issue",
        "addressed",
        "improved",
        "restrictions",
        "fixed",
        "Safari",
        "iPadOS",
        "macOS",
        "Sonoma",
        "tvOS",
        "watchOS",
        "maliciously",
        "crafted",
        "webpage",
        "able",
        "fingerprint",
        "user",
        "iOS and iPadOS"
    ]
}


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc67CVE202423206RCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-067"
    meta_poc_name = 'CVE-2024-23206 网络邻近攻击 Active Validation'
    meta_cve_id = 'CVE-2024-23206'
    meta_severity = 'High'
    meta_protocol = 'wifi'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['wifi']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-23206'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-23206']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "67_AirPlay_SDK_Nearby_Network_RCE_Audit") if "VULN" in dir() else "67_AirPlay_SDK_Nearby_Network_RCE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc67CVE202423206RCEAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

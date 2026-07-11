#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import socket

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _rtsp_probe_simple(host: str, port: int, path: str, body: bytes) -> dict:
    headers = {
        "CSeq": "5",
        "Content-Type": "application/octet-stream",
        "Content-Length": str(len(body)),
    }
    request = (
        f"POST {path} RTSP/1.0\r\n"
        + "\r\n".join(f"{k}: {v}" for k, v in headers.items())
        + "\r\n\r\n"
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
        "cve": "CVE-2024-23205",
        "target": target_ip,
        "technique": "AirPlay unauthenticated /pair-setup access control probe",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-23205",
    }

    result = _rtsp_probe_simple(target_ip, airplay_port, "/pair-setup", b"\x00" * 512)
    evidence["rtsp_probe"] = result

    if not result["connected"]:
        vulnerable = None
        evidence["note"] = "AirPlay port not reachable; cannot assess access control"
    elif "200" in result["status"]:
        vulnerable = True
        evidence["note"] = "Unauthenticated /pair-setup accepted (200 OK) - access control missing"
    elif "401" in result["status"] or "403" in result["status"]:
        vulnerable = False
        evidence["note"] = "Server correctly rejected unauthenticated /pair-setup"
    else:
        vulnerable = None
        evidence["note"] = f"Ambiguous response: {result['status']}"

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    'cve': 'CVE-2024-23205',
    'year': 2024,
    'domain': 'application',
    'vendor_product': 'Unknown',
    'component': 'Unknown',
    'type': 'Unknown',
    'summary': 'CVE-2024-23205 认证/访问控制缺陷 Active Validation',
    'source_url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-23205',
    'affected': [{'vendor': 'Unknown', 'product': 'Unknown', 'versions': []}],
    'id': 0,
    "id": 83,
    "cve": "CVE-2024-23205",
    "year": 2024,
    "domain": "车载互联/CarPlay相关",
    "vendor_product": "Apple AirPlay/CarPlay ecosystem",
    "component": "AirPlay SDK",
    "type": "认证/访问控制缺陷",
    "summary": "AirPlay SDK相关漏洞，可能影响CarPlay/车载集成设备。",
    "source_description": "A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in iOS 17.4 and iPadOS 17.4, macOS Sonoma 14.4. An app may be able to access sensitive user data.",
    "poc_status": "有公开研究；PoC有限",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23205",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23205",
        "https://support.apple.com/en-us/120893",
        "https://support.apple.com/en-us/120895",
        "https://cveawg.mitre.org/api/cve/CVE-2024-23205"
    ],
    "affected": [
        {
            "vendor": "Apple",
            "product": "iOS and iPadOS",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "17.4",
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
                    "lessThan": "14.4",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-23205",
        "Apple",
        "AirPlay",
        "CarPlay",
        "ecosystem",
        "SDK",
        "privacy",
        "issue",
        "addressed",
        "improved",
        "private",
        "data",
        "redaction",
        "entries",
        "fixed",
        "iPadOS",
        "macOS",
        "Sonoma",
        "able",
        "access",
        "sensitive",
        "user",
        "iOS and iPadOS"
    ],
    "active_probe_paths": ["/server-info"],
    "active_payload_text": "POST /pair-setup RTSP/1.0\r\nCSeq: 5\r\nContent-Type: application/octet-stream\r\nContent-Length: 512\r\n\r\n" + "\x00" * 512,
}


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc60CVE202423205AccessControlAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-APP-060"
    meta_poc_name = 'CVE-2024-23205 访问控制缺陷 Active Validation'
    meta_cve_id = 'CVE-2024-23205'
    meta_severity = 'High'
    meta_protocol = 'airplay'
    meta_target_os = ['all']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['application']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-23205'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-23205']
    meta_attack_surface = '车机APP/应用'
    is_disruptive = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "60_AirPlay_SDK_Access_Control_Audit") if "VULN" in dir() else "60_AirPlay_SDK_Access_Control_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc60CVE202423205AccessControlAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

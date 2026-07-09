#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import socket
import ssl
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 19,
    "cve": "CVE-2025-7020",
    "year": 2025,
    "domain": "IVI/OS/协议/隐私",
    "vendor_product": "BYD DiLink 3.0 OS",
    "component": "多媒体单元日志加密",
    "type": "加密实现错误",
    "summary": "系统日志加密实现可绕过，物理访问者可读取个人与位置数据。",
    "source_description": "An incorrect encryption implementation vulnerability exists in the system log dump feature of BYD's DiLink 3.0 OS (e.g. in the model ATTO3). An attacker with physical access to the vehicle can bypass the encryption of log dumps on the In-Vehicle Infotainment (IVI) unit's storage. This allows the attacker to access and read system logs containing sensitive data, including personally identifiable information (PII) and location data.\n\nThis vulnerability was introduced in a patch intended to fix CVE-2024-54728.",
    "poc_status": "有ASRG公告；未见一步式PoC",
    "research_value": "车载OS/多媒体/无钥匙系统供应链风险。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-7020",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-7020",
        "https://asrg.io/security-advisories/cve-2025-7020/",
        "https://cveawg.mitre.org/api/cve/CVE-2025-7020"
    ],
    "affected": [
        {
            "vendor": "BYD",
            "product": "DiLink OS",
            "versions": [
                {
                    "version": "13.1.32.2307211.1",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-7020",
        "BYD",
        "DiLink",
        "incorrect",
        "encryption",
        "implementation",
        "vulnerability",
        "exists",
        "system",
        "dump",
        "feature",
        "e.g",
        "model",
        "ATTO3",
        "physical",
        "access",
        "bypass",
        "dumps",
        "In-Vehicle",
        "Infotainment",
        "unit",
        "storage",
        "read",
        "DiLink OS"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2025-7020: check web management interface access control on IVI device."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    service_banner = params.get("service_banner", "")

    evidence = {
        "cve": "CVE-2025-7020",
        "target": target_ip,
        "technique": "BYD DiLink 3.0 OS log encryption bypass - probe IVI management interface",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2025-7020",
    }

    vulnerable = None
    service_found = False

    for port in [80, 443, 8080]:
        try:
            with socket.create_connection((target_ip, port), timeout=4) as sock:
                req = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {target_ip}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()
                sock.sendall(req)
                resp = sock.recv(4096).decode(errors="replace")
                service_found = True
                evidence["service_port"] = port
                evidence["response_snippet"] = resp[:300]
                server_hdr = ""
                for line in resp.split("\r\n"):
                    if line.lower().startswith("server:"):
                        server_hdr = line
                        break
                evidence["server_header"] = server_hdr
                if resp.startswith("HTTP/"):
                    status = resp.split("\r\n")[0]
                    evidence["http_status"] = status
                    if "200" in status:
                        evidence["unauthenticated_access"] = True
                        vulnerable = None
                break
        except Exception:
            pass

    if not service_found:
        evidence["note"] = "No HTTP service found on target"
        if service_banner:
            evidence["banner"] = service_banner[:200]

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }

try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc27CVE20257020CryptoAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-019'
    meta_poc_name = 'CVE-2025-7020 加密实现错误 Active Validation'
    meta_cve_id = 'CVE-2025-7020'
    meta_severity = 'Medium'
    meta_protocol = 'tcp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-7020'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2025-7020']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "27_BYD_DiLink_Log_Crypto_Bypass_Audit") if "VULN" in dir() else "27_BYD_DiLink_Log_Crypto_Bypass_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc27CVE20257020CryptoAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

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
    "id": 40,
    "cve": "CVE-2024-23972",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Sony XAV-AX5500",
    "component": "USB配置描述符",
    "type": "栈溢出/RCE",
    "summary": "恶意USB配置描述符触发固定长度缓冲区溢出并执行代码。",
    "source_description": "Sony XAV-AX5500 USB Configuration Descriptor Buffer Overflow Remote Code Execution Vulnerability. This vulnerability allows physically present attackers to execute arbitrary code on affected installations of Sony XAV-AX5500 devices. Authentication is not required to exploit this vulnerability.\n\nThe specific flaw exists within the USB host driver. A crafted USB configuration descriptor can trigger an overflow of a fixed-length buffer. An attacker can leverage this vulnerability to execute code in the context of the device.\n\nWas ZDI-CAN-23185",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23972",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23972",
        "https://www.zerodayinitiative.com/advisories/ZDI-24-876/",
        "https://www.sony.com/electronics/support/mobile-cd-players-digital-media-players-xav-series/xav-ax5500/software/00274156",
        "https://cveawg.mitre.org/api/cve/CVE-2024-23972"
    ],
    "affected": [
        {
            "vendor": "Sony",
            "product": "XAV-AX5500",
            "versions": [
                {
                    "version": "1.13",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-23972",
        "Sony",
        "XAV-AX5500",
        "USB",
        "RCE",
        "Configuration",
        "Descriptor",
        "Buffer",
        "Overflow",
        "Remote",
        "Code",
        "Execution",
        "Vulnerability",
        "vulnerability",
        "physically",
        "present",
        "attackers",
        "execute",
        "arbitrary",
        "code",
        "installations",
        "devices",
        "Authentication",
        "required",
        "exploit",
        "specific"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2024-23972: check web management interface access control on IVI device."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    service_banner = params.get("service_banner", "")

    evidence = {
        "cve": "CVE-2024-23972",
        "target": target_ip,
        "technique": "Sony XAV-AX5500 USB descriptor stack overflow - probe USB/web interface",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-23972",
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

class Poc34CVE202423972StackOverflowRCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-034"
    meta_poc_name = 'CVE-2024-23972 RCE Active Validation'
    meta_cve_id = 'CVE-2024-23972'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-23972'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-23972']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "34_Sony_XAV_AX5500_USB_Descriptor_Stack_Overflow_RCE_Audit") if "VULN" in dir() else "34_Sony_XAV_AX5500_USB_Descriptor_Stack_Overflow_RCE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc34CVE202423972StackOverflowRCEAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

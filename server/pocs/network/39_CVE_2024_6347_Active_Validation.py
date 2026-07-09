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
    "id": 45,
    "cve": "CVE-2024-6347",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Automotive backend/charger component",
    "component": "关键功能接口",
    "type": "缺少认证/授权不当",
    "summary": "关键功能缺少认证并存在授权问题。",
    "source_description": "*  Unprotected privileged mode access through UDS session in the Blind Spot Detection Sensor ECU firmware in Nissan Altima (2022) allows attackers to trigger denial-of-service (DoS) by unauthorized access to the ECU's programming session.\n  *  No preconditions implemented for ECU management functionality through UDS session in the Blind Spot Detection Sensor ECU in Nissan Altima (2022) allows attackers to disrupt normal ECU operations by triggering a control command without authentication.",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6347",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-6347",
        "https://asrg.io/security-advisories/CVE-2024-6347",
        "https://cveawg.mitre.org/api/cve/CVE-2024-6347"
    ],
    "affected": [
        {
            "vendor": "Nissan",
            "product": "Altima",
            "versions": [
                {
                    "version": "Altima 2022",
                    "status": "unknown"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-6347",
        "Automotive",
        "backend",
        "charger",
        "component",
        "Unprotected",
        "privileged",
        "mode",
        "access",
        "session",
        "Blind",
        "Spot",
        "Detection",
        "Sensor",
        "firmware",
        "Nissan",
        "Altima",
        "attackers",
        "trigger",
        "denial-of-service",
        "unauthorized",
        "programming",
        "preconditions",
        "implemented",
        "management",
        "functionality"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2024-6347: access admin endpoints without auth (Spring Boot actuator + custom)."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 8080))
    tls = bool(params.get("tls", False))

    evidence = {
        "cve": "CVE-2024-6347",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP behavioral probe - unauthenticated admin/internal/actuator endpoint access",
    }

    active_port = None
    for try_port in [port, 80, 443, 8080, 8443, 9000]:
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

    admin_paths = ["/api/admin", "/internal", "/debug", "/actuator", "/actuator/env",
                   "/actuator/health", "/actuator/metrics", "/management", "/admin"]
    accessible_paths = []
    for path in admin_paths:
        r = probe.get(path)
        status = r.get("status")
        evidence[f"path_{path.strip('/').replace('/', '_')}_status"] = status
        if status == 200:
            accessible_paths.append(path)
            evidence["unauth_admin_access"] = True
            evidence["accessible_path"] = path
            evidence["body_preview"] = r.get("body_text", "")[:200]

    evidence["admin_paths_tested"] = admin_paths

    if accessible_paths:
        return {
            "vulnerable": True,
            "evidence": evidence,
            "detection_confidence": detection_confidence("B", evidence, "unauthenticated_admin_endpoint"),
            "requires_manual_review": False,
        }

    r_root = probe.get("/")
    evidence["http_status"] = r_root.get("status")
    evidence["server_header"] = r_root.get("headers", {}).get("Server", "")

    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("C", evidence, "admin_endpoints_blocked"),
        "requires_manual_review": True,
    }

class Poc39CVE20246347ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-045'
    meta_poc_name = 'CVE-2024-6347 授权不当 Active Validation'
    meta_cve_id = 'CVE-2024-6347'
    meta_severity = 'High'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-6347'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-6347']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "39_Automotive_Backend_Missing_Auth_Authorization_Audit") if "VULN" in dir() else "39_Automotive_Backend_Missing_Auth_Authorization_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc39CVE20246347ExposureAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

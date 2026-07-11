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
    "id": 43,
    "cve": "CVE-2024-6245",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Maruti Suzuki SmartPlay",
    "component": "Linux infotainment hub",
    "type": "默认凭据",
    "summary": "SmartPlay IVI使用默认凭据，攻击者可尝试常见用户名/密码。",
    "source_description": "Use of Default Credentials vulnerability in Maruti Suzuki SmartPlay on Linux (Infotainment Hub modules) allows attacker to try common or default usernames and passwords.The issue was detected on a 2022 Maruti Suzuki Brezza in India Market.\n\nThis issue affects SmartPlay: 66T0.05.50.",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6245",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-6245",
        "https://www.marutisuzuki.com/corporate/technology/smartplay-systems",
        "https://www.global-infotainment-system.com/en/top.html",
        "https://cveawg.mitre.org/api/cve/CVE-2024-6245"
    ],
    "affected": [
        {
            "vendor": "Faurecia Clarion Electronics Co., Ltd.",
            "product": "SmartPlay",
            "versions": [
                {
                    "version": "66T0.05.50",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-6245",
        "Maruti",
        "Suzuki",
        "SmartPlay",
        "Linux",
        "infotainment",
        "hub",
        "Default",
        "Credentials",
        "vulnerability",
        "Infotainment",
        "modules",
        "common",
        "default",
        "usernames",
        "passwords.The",
        "issue",
        "detected",
        "Brezza",
        "India",
        "Market",
        "affects",
        "T0.05.50",
        "Faurecia Clarion Electronics Co., Ltd"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2024-6245: Maruti SmartPlay default credentials with full credential list."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 80))
    tls = bool(params.get("tls", False))

    evidence = {
        "cve": "CVE-2024-6245",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP default credential probe - Maruti SmartPlay IVI web interface",
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

    cred_result = http_default_creds_probe(
        target_ip, active_port, tls,
        paths=["/admin", "/login", "/management", "/api/auth", "/webui", "/api/v1/user"],
        cred_pairs=[
            ("admin", "admin"), ("root", "root"), ("admin", "password"),
            ("admin", "admin123"), ("user", "user"), ("guest", "guest"),
            ("admin", ""), ("root", ""), ("admin", "1234"), ("admin", "12345"),
        ],
    )
    evidence["credential_probe"] = cred_result

    if cred_result.get("success"):
        evidence["default_creds_found"] = True
        evidence["credential"] = cred_result.get("credential")
        evidence["successful_path"] = cred_result.get("path")
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

class Poc37CVE20246245ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-037"
    meta_poc_name = 'CVE-2024-6245 默认凭据 Active Validation'
    meta_cve_id = 'CVE-2024-6245'
    meta_severity = 'Medium'
    meta_protocol = 'https'
    meta_target_os = ['linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-6245'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-6245']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "37_Maruti_SmartPlay_Default_Credentials_Audit") if "VULN" in dir() else "37_Maruti_SmartPlay_Default_Credentials_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc37CVE20246245ExposureAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

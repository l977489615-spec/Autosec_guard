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
    "id": 52,
    "cve": "CVE-2023-28895",
    "year": 2023,
    "domain": "IVI/云端/EVSE/OS",
    "vendor_product": "Automotive backend/Skoda/VW ecosystem",
    "component": "credentials",
    "type": "硬编码凭据",
    "summary": "车联网服务/组件存在硬编码凭据风险。",
    "source_description": "The password for access to the debugging console of the PoWer Controller chip (PWC) of the MIB3 infotainment is hard-coded in the firmware. The console allows attackers with physical access to the MIB3 unit to gain full control over the PWC chip.\n\nVulnerability found on Škoda Superb III (3V3) - 2.0 TDI manufactured in 2022.",
    "poc_status": "公开公告；大多未见一步式PoC",
    "research_value": "作为近两年前后演进基线，对比2024-2026风险变化。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-28895",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-28895",
        "https://asrg.io/security-advisories/hard-coded-password-for-access-to-power-controller-chip-memory/",
        "https://cveawg.mitre.org/api/cve/CVE-2023-28895"
    ],
    "affected": [
        {
            "vendor": "JOYNEXT",
            "product": "MIB3 Infotainment Unit",
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
        "CVE-2023-28895",
        "Automotive",
        "backend",
        "Skoda",
        "ecosystem",
        "credentials",
        "password",
        "access",
        "debugging",
        "console",
        "PoWer",
        "Controller",
        "chip",
        "MIB3",
        "infotainment",
        "hard-coded",
        "firmware",
        "attackers",
        "physical",
        "unit",
        "gain",
        "full",
        "control",
        "over",
        "Vulnerability",
        "found",
        "koda",
        "Superb",
        "manufactured",
        "JOYNEXT"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2023-28895: MIB3 hardcoded credentials with automotive-specific default passwords."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 80))
    tls = bool(params.get("tls", False))

    evidence = {
        "cve": "CVE-2023-28895",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP default credential probe - MIB3/automotive-specific hardcoded password check",
    }

    active_port = None
    for try_port in [port, 80, 443, 8080, 23]:
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
        paths=["/admin", "/login", "/debug", "/console", "/management", "/api/auth"],
        cred_pairs=[
            ("admin", "admin"), ("root", "root"), ("user", "user"),
            ("admin", "password"), ("root", "toor"), ("guest", "guest"),
            ("admin", ""), ("root", ""), ("mib3", "mib3"),
            ("joynext", "joynext"), ("preh", "preh"),
        ],
    )
    evidence["credential_probe"] = cred_result

    if cred_result.get("success"):
        evidence["hardcoded_creds_found"] = True
        evidence["credential"] = cred_result.get("credential")
        return {
            "vulnerable": True,
            "evidence": evidence,
            "detection_confidence": detection_confidence("B", evidence, "hardcoded_credential_confirmed"),
            "requires_manual_review": False,
        }

    probe = HTTPProbe(target_ip, active_port, tls=tls)
    r_root = probe.get("/")
    evidence["http_status"] = r_root.get("status")
    evidence["server_header"] = r_root.get("headers", {}).get("Server", "")

    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("B", evidence, "hardcoded_creds_not_found"),
        "requires_manual_review": True,
    }

class Poc45CVE202328895ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-045"
    meta_poc_name = 'CVE-2023-28895 硬编码凭据 Active Validation'
    meta_cve_id = 'CVE-2023-28895'
    meta_severity = 'High'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-28895'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2023-28895']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "45_Automotive_Backend_Hardcoded_Credentials_Audit") if "VULN" in dir() else "45_Automotive_Backend_Hardcoded_Credentials_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc45CVE202328895ExposureAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

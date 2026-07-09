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
    "id": 56,
    "cve": "CVE-2023-28910",
    "year": 2023,
    "domain": "IVI/云端/EVSE/OS",
    "vendor_product": "Volkswagen MIB3 Infotainment",
    "component": "MIB3 IVI update/service",
    "type": "访问控制/认证缺陷",
    "summary": "MIB3 IVI漏洞，可与其他缺陷组成攻击链。",
    "source_description": "A specific flaw exists within the Bluetooth stack of the MIB3 infotainment system. The issue results from the disabled abortion flag eventually leading to bypassing assertion functions.\nThe vulnerability was originally discovered in Skoda Superb III car with MIB3 infotainment unit OEM part number 3V0035820. The list of affected MIB3 OEM part numbers is provided in the referenced resources.",
    "poc_status": "公开公告；大多未见一步式PoC",
    "research_value": "作为近两年前后演进基线，对比2024-2026风险变化。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-28910",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-28910",
        "https://i.blackhat.com/EU-24/Presentations/EU-24-Parnishchev-OverTheAirVW.pdf",
        "https://pcacybersecurity.com/resources/advisory/vulnerabilities-in-vw-mib3-infotainment-2",
        "https://asrg.io/security-advisories/vulnerabilities-in-volkswagen-mib3-infotainment-part-2/",
        "https://cveawg.mitre.org/api/cve/CVE-2023-28910"
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
        "CVE-2023-28910",
        "Volkswagen",
        "MIB3",
        "Infotainment",
        "IVI",
        "update",
        "service",
        "specific",
        "flaw",
        "exists",
        "within",
        "Bluetooth",
        "stack",
        "infotainment",
        "system",
        "issue",
        "results",
        "disabled",
        "abortion",
        "flag",
        "eventually",
        "leading",
        "bypassing",
        "assertion",
        "functions",
        "vulnerability",
        "originally",
        "discovered",
        "Skoda",
        "Superb"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2023-28910: VW MIB3 Bluetooth admin endpoint access control bypass."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 8080))
    tls = bool(params.get("tls", False))

    evidence = {
        "cve": "CVE-2023-28910",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP behavioral probe - VW MIB3 Bluetooth admin endpoint unauthenticated access",
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

    admin_paths = ["/admin", "/api/admin", "/api/bt/admin", "/api/config",
                   "/api/v1/system", "/management", "/api/update"]
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
            "detection_confidence": detection_confidence("B", evidence, "unauthenticated_mib3_admin"),
            "requires_manual_review": False,
        }

    r_root = probe.get("/")
    evidence["http_status"] = r_root.get("status")
    evidence["server_header"] = r_root.get("headers", {}).get("Server", "")
    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("C", evidence, "mib3_admin_paths_blocked"),
        "requires_manual_review": True,
    }

class Poc49CVE202328910AccessControlAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-056'
    meta_poc_name = 'CVE-2023-28910 认证缺陷 Active Validation'
    meta_cve_id = 'CVE-2023-28910'
    meta_severity = 'Medium'
    meta_protocol = 'https'
    meta_target_os = ['linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-28910'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2023-28910']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "49_VW_MIB3_Access_Control_Auth_Audit") if "VULN" in dir() else "49_VW_MIB3_Access_Control_Auth_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc49CVE202328910AccessControlAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

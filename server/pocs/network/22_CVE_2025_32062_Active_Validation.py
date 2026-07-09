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
    "id": 7,
    "cve": "CVE-2025-32062",
    "year": 2025,
    "domain": "IVI/CAN/OTA",
    "vendor_product": "Nissan Leaf ZE1 / Bosch Infotainment ECU",
    "component": "Linux IVI、RH850 CAN模块、Redbend OTA",
    "type": "访问控制缺陷",
    "summary": "Nissan Leaf Bosch IVI关键配置/服务访问控制不足。",
    "source_description": "The specific flaw exists within the Bluetooth stack developed by Alps Alpine of the Infotainment ECU manufactured by Bosch. The issue results from the lack of proper boundary validation of user-supplied data, which can result in a stack-based buffer overflow when receiving a specific packet on the established upper layer L2CAP channel. An attacker can leverage this vulnerability to obtain remote code execution on the Infotainment ECU with root privileges.\n\n\n\nFirst identified on Nissan Leaf ZE1 manufactured in 2020.",
    "poc_status": "有公开BlackHat/PCA研究材料；未整理为一步式PoC",
    "research_value": "适合研究IVI到CAN边界突破、OTA信任链、域间横向移动。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-32062",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-32062",
        "https://www.nissan.co.uk/vehicles/new-vehicles/leaf.html",
        "http://i.blackhat.com/Asia-25/Asia-25-Evdokimov-Remote-Exploitation-of-Nissan-Leaf.pdf",
        "https://pcacybersecurity.com/resources/advisory/vulnerabilities-in-nissan-infotainment-manufactured-by-bosch",
        "https://cveawg.mitre.org/api/cve/CVE-2025-32062"
    ],
    "affected": [
        {
            "vendor": "Bosch",
            "product": "Infotainment system ECU",
            "versions": [
                {
                    "version": "283C30861E",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-32062",
        "Nissan",
        "Leaf",
        "ZE1",
        "Bosch",
        "Infotainment",
        "ECU",
        "Linux",
        "IVI",
        "RH850",
        "CAN",
        "Redbend",
        "OTA",
        "specific",
        "flaw",
        "exists",
        "within",
        "Bluetooth",
        "stack",
        "developed",
        "Alps",
        "Alpine",
        "manufactured",
        "issue",
        "results",
        "lack",
        "proper",
        "boundary",
        "validation",
        "user-supplied"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2025-32062: missing auth on admin endpoints of Bosch IVI."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 8080))
    tls = bool(params.get("tls", False))

    evidence = {
        "cve": "CVE-2025-32062",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP behavioral probe - unauthenticated access to Bosch IVI admin endpoints",
    }

    active_port = None
    for try_port in [port, 8080, 8443, 80, 443, 9000]:
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

    admin_paths = ["/admin", "/api/admin", "/config", "/api/config", "/management", "/api/management"]
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
    evidence["http_status_root"] = r_root.get("status")
    evidence["server_header"] = r_root.get("headers", {}).get("Server", "")

    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("C", evidence, "admin_paths_blocked"),
        "requires_manual_review": True,
    }

class Poc22CVE202532062AccessControlAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-007'
    meta_poc_name = 'CVE-2025-32062 访问控制缺陷 Active Validation'
    meta_cve_id = 'CVE-2025-32062'
    meta_severity = 'High'
    meta_protocol = 'can'
    meta_target_os = ['linux']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-32062'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2025-32062']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "22_Nissan_Bosch_IVI_Access_Control_Audit") if "VULN" in dir() else "22_Nissan_Bosch_IVI_Access_Control_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc22CVE202532062AccessControlAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

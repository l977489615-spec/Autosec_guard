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
    "id": 41,
    "cve": "CVE-2024-1633",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Automotive embedded component",
    "component": "车载软件组件",
    "type": "访问控制/输入校验",
    "summary": "ASRG披露的车载组件漏洞，影响智能车生态组件。",
    "source_description": "During the secure boot, bl2 (the second stage of\nthe bootloader) loops over images defined in the table “bl2_mem_params_descs”.\nFor each image, the bl2 reads the image length and destination from the image’s\ncertificate. Because of the way of reading from the image, which base on 32-bit unsigned integer value, it can result to an integer overflow. An attacker can bypass memory range restriction and write data out of buffer bounds, which could result in bypass of secure boot.\n\n Affected git version from c2f286820471ed276c57e603762bd831873e5a17 until (not \n",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1633",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-1633",
        "https://asrg.io/security-advisories/CVE-2024-1633/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-1633"
    ],
    "affected": [
        {
            "vendor": "Renesas",
            "product": "rcar_gen3_v2.5",
            "versions": [
                {
                    "version": "v2.5",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-1633",
        "Automotive",
        "embedded",
        "component",
        "During",
        "secure",
        "boot",
        "second",
        "stage",
        "bootloader",
        "loops",
        "over",
        "images",
        "defined",
        "table",
        "bl2_mem_params_descs",
        "each",
        "image",
        "reads",
        "length",
        "destination",
        "certificate",
        "Because",
        "reading",
        "which",
        "base",
        "unsigned",
        "integer",
        "value",
        "Renesas"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2024-1633: test common automotive backend API endpoints for auth bypass."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 8080))
    tls = bool(params.get("tls", False))

    evidence = {
        "cve": "CVE-2024-1633",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP behavioral probe - unauthenticated access to automotive backend API endpoints",
    }

    active_port = None
    for try_port in [port, 80, 443, 8080, 9000]:
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

    admin_paths = ["/api/v1/status", "/api/vehicles", "/api/config", "/admin", "/api/admin", "/management"]
    accessible_paths = []
    for path in admin_paths:
        r = probe.get(path)
        status = r.get("status")
        evidence[f"path_{path.strip('/').replace('/', '_')}_status"] = status
        if status == 200:
            accessible_paths.append(path)
            evidence["unauth_access"] = True
            evidence["accessible_path"] = path
            evidence["body_preview"] = r.get("body_text", "")[:200]

    evidence["admin_paths_tested"] = admin_paths

    if accessible_paths:
        return {
            "vulnerable": True,
            "evidence": evidence,
            "detection_confidence": detection_confidence("B", evidence, "unauthenticated_api_endpoint"),
            "requires_manual_review": False,
        }

    r_root = probe.get("/")
    evidence["http_status"] = r_root.get("status")
    evidence["server_header"] = r_root.get("headers", {}).get("Server", "")
    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("C", evidence, "api_endpoints_blocked"),
        "requires_manual_review": True,
    }

class Poc35CVE20241633AccessControlInputValidationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-041'
    meta_poc_name = 'CVE-2024-1633 输入校验 Active Validation'
    meta_cve_id = 'CVE-2024-1633'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-1633'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-1633']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "35_Automotive_Component_Access_Control_Input_Validation_Audit") if "VULN" in dir() else "35_Automotive_Component_Access_Control_Input_Validation_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc35CVE20241633AccessControlInputValidationAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

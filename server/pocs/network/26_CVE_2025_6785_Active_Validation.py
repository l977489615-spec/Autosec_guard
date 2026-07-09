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
    "id": 18,
    "cve": "CVE-2025-6785",
    "year": 2025,
    "domain": "IVI/OS/协议/隐私",
    "vendor_product": "Tesla Model 3",
    "component": "车载物理接口/输出处理",
    "type": "注入/物理访问控制不足",
    "summary": "Tesla Model 3 2023.xx < 2023.44存在注入与物理访问控制问题。",
    "source_description": "Securing externally available CAN wires can easily allow physical access to the CAN bus, allowing possible injection of specially formed CAN messages to control remote start functions of the vehicle.  Testing completed on Tesla Model 3 vehicles with software version v11.1 (2023.20.9 ee6de92ddac5). This issue affects Model 3: With software versions from 2023.Xx before 2023.44.",
    "poc_status": "未见通用PoC；有ASRG/NVD披露",
    "research_value": "车载OS/多媒体/无钥匙系统供应链风险。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-6785",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-6785",
        "https://asrg.io/security-advisories/cve-2025-6785/",
        "https://cveawg.mitre.org/api/cve/CVE-2025-6785"
    ],
    "affected": [
        {
            "vendor": "Tesla",
            "product": "Model 3",
            "versions": [
                {
                    "version": "2023.xx",
                    "status": "affected",
                    "lessThan": "2023.44",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-6785",
        "Tesla",
        "Model",
        "Securing",
        "externally",
        "available",
        "wires",
        "easily",
        "allow",
        "physical",
        "access",
        "allowing",
        "possible",
        "injection",
        "specially",
        "formed",
        "messages",
        "control",
        "remote",
        "start",
        "functions",
        "Testing",
        "completed",
        "software",
        "v11.1",
        "ee6de92ddac5",
        "Model 3"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2025-6785: Tesla API unauthenticated endpoint exposure check."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 4070))
    tls = bool(params.get("tls", False))

    evidence = {
        "cve": "CVE-2025-6785",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP behavioral probe - Tesla BLE/Wi-Fi API unauthenticated endpoint check",
    }

    active_port = None
    for try_port in [port, 4070, 80, 443, 8080, 8443]:
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

    tesla_paths = ["/version", "/api/1/vehicles", "/api/1/status", "/api/version", "/"]
    for path in tesla_paths:
        r = probe.get(path)
        status = r.get("status")
        body = r.get("body_text", "")
        evidence[f"path_{path.strip('/').replace('/', '_') or 'root'}_status"] = status
        if status == 200:
            evidence["accessible_path"] = path
            evidence["body_preview"] = body[:200]
            if any(kw in body.lower() for kw in ["tesla", "vehicle", "vin", "version", "software"]):
                evidence["tesla_api_indicator"] = True
            return {
                "vulnerable": None,
                "evidence": evidence,
                "detection_confidence": detection_confidence("B", evidence, "tesla_api_accessible"),
                "requires_manual_review": True,
            }

    evidence["tesla_paths_tested"] = tesla_paths
    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("C", evidence, "http_service_probed"),
        "requires_manual_review": True,
    }

class Poc26CVE20256785AccessControlInjectionAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-018'
    meta_poc_name = 'CVE-2025-6785 物理访问控制不足 Active Validation'
    meta_cve_id = 'CVE-2025-6785'
    meta_severity = 'High'
    meta_protocol = 'tcp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-6785'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2025-6785']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "26_Tesla_Model3_Physical_Access_Injection_Audit") if "VULN" in dir() else "26_Tesla_Model3_Physical_Access_Injection_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc26CVE20256785AccessControlInjectionAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

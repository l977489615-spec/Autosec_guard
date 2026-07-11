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
    "id": 38,
    "cve": "CVE-2024-23960",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Alpine Halo9",
    "component": "固件元数据签名",
    "type": "签名校验不当",
    "summary": "物理攻击者可绕过签名校验，配合其他漏洞root代码执行。",
    "source_description": "Alpine Halo9 Improper Verification of Cryptographic Signature Vulnerability. This vulnerability allows physically present attackers to bypass signature validation mechanism on affected installations of Alpine Halo9 devices. Authentication is not required to exploit this vulnerability.\n\nThe specific flaw exists within the firmware metadata signature validation mechanism. The issue results from the lack of proper verification of a cryptographic signature. An attacker can leverage this in conjunction with other vulnerabilities to execute arbitrary code in the context of root.\n\nWas ZDI-CAN-23102",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23960",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23960",
        "https://www.zerodayinitiative.com/advisories/ZDI-24-845/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-23960"
    ],
    "affected": [
        {
            "vendor": "Alpine",
            "product": "Halo9",
            "versions": [
                {
                    "version": "6.0.000",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-23960",
        "Alpine",
        "Halo9",
        "Improper",
        "Verification",
        "Cryptographic",
        "Signature",
        "Vulnerability",
        "vulnerability",
        "physically",
        "present",
        "attackers",
        "bypass",
        "signature",
        "validation",
        "mechanism",
        "installations",
        "devices",
        "Authentication",
        "required",
        "exploit",
        "specific",
        "flaw",
        "exists"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2024-23960: Alpine Halo9 firmware signature bypass via update endpoint probe."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 80))
    tls = bool(params.get("tls", False))

    evidence = {
        "cve": "CVE-2024-23960",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP behavioral probe - Alpine Halo9 firmware signature bypass via update endpoint",
    }

    active_port = None
    for try_port in [port, 80, 8080, 443]:
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
    body_root = r_root.get("body_text", "").lower()
    if any(kw in body_root for kw in ["alpine", "halo9", "halo-9"]):
        evidence["alpine_banner_match"] = True

    update_endpoints = ["/update", "/firmware", "/upgrade", "/fwupdate", "/ota", "/fw/update"]
    accessible = []
    for ep in update_endpoints:
        r = probe.get(ep)
        status = r.get("status")
        evidence[f"GET_{ep.strip('/')}_status"] = status
        if status in (200, 201, 202, 301, 302):
            accessible.append(ep)

    if accessible:
        evidence["update_endpoint_accessible"] = accessible[0]
        evidence["update_endpoints_accessible"] = accessible
        fake_meta = b'{"version":"9.9.9","signature":"INVALID_SIG_BYPASS_TEST"}'
        r_post = probe.post(accessible[0], fake_meta, "application/json")
        evidence["signature_bypass_post_status"] = r_post.get("status")
        evidence["signature_bypass_response"] = r_post.get("body_text", "")[:200]
        if r_post.get("status") not in (401, 403, None):
            evidence["signature_bypass_accepted"] = True
        return {
            "vulnerable": None,
            "evidence": evidence,
            "detection_confidence": detection_confidence("B", evidence, "firmware_endpoint_signature_probe"),
            "requires_manual_review": True,
        }

    evidence["update_endpoints_tested"] = update_endpoints
    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("C", evidence, "update_endpoint_not_found"),
        "requires_manual_review": True,
    }

class Poc32CVE202423960SignatureVerificationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-032"
    meta_poc_name = 'CVE-2024-23960 签名校验不当 Active Validation'
    meta_cve_id = 'CVE-2024-23960'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-23960'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-23960']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "32_Alpine_Halo9_Firmware_Signature_Verification_Audit") if "VULN" in dir() else "32_Alpine_Halo9_Firmware_Signature_Verification_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc32CVE202423960SignatureVerificationAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

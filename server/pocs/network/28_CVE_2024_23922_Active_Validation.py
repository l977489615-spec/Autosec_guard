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
    "id": 34,
    "cve": "CVE-2024-23922",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Sony XAV-AX5500",
    "component": "固件更新",
    "type": "更新包校验不足/RCE",
    "summary": "固件更新包缺少真实性校验，物理访问者可执行设备上下文代码。",
    "source_description": "Sony XAV-AX5500 Insufficient Firmware Update Validation Remote Code Execution Vulnerability. This vulnerability allows physically present attackers to execute arbitrary code on affected installations of Sony XAV-AX5500 devices. Authentication is not required to exploit this vulnerability.\n\nThe specific flaw exists within the handling of software updates. The issue results from the lack of proper validation of software update packages. An attacker can leverage this vulnerability to execute code in the context of the device.\n\nWas ZDI-CAN-22939",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23922",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23922",
        "https://www.zerodayinitiative.com/advisories/ZDI-24-874/",
        "https://www.sony.com/electronics/support/mobile-cd-players-digital-media-players-xav-series/xav-ax5500/software/00274156",
        "https://cveawg.mitre.org/api/cve/CVE-2024-23922"
    ],
    "affected": [
        {
            "vendor": "Sony",
            "product": "XAV-AX5500",
            "versions": [
                {
                    "version": "1.13",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-23922",
        "Sony",
        "XAV-AX5500",
        "RCE",
        "Insufficient",
        "Firmware",
        "Update",
        "Validation",
        "Remote",
        "Code",
        "Execution",
        "Vulnerability",
        "vulnerability",
        "physically",
        "present",
        "attackers",
        "execute",
        "arbitrary",
        "code",
        "installations",
        "devices",
        "Authentication",
        "required",
        "exploit",
        "specific"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2024-23922: Sony XAV-AX5500 firmware update endpoint with multipart POST."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 80))
    tls = bool(params.get("tls", False))

    evidence = {
        "cve": "CVE-2024-23922",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP behavioral probe - POST multipart firmware payload to Sony XAV-AX5500 update endpoint",
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

    update_endpoints = ["/update", "/firmware", "/upgrade", "/fwupdate", "/ota", "/firmware_update"]
    accessible_endpoints = []
    for ep in update_endpoints:
        r = probe.get(ep)
        status = r.get("status")
        evidence[f"GET_{ep.strip('/')}_status"] = status
        if status in (200, 201, 202, 301, 302):
            accessible_endpoints.append(ep)

    if accessible_endpoints:
        evidence["update_endpoint_accessible"] = accessible_endpoints[0]
        boundary = "----FirmwareBoundary7MA4YWxkTrZu0gW"
        fake_fw = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="firmware"; filename="update.bin"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
            "FAKE_FW_PAYLOAD_PROBE_ONLY\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        r_post = probe.post(
            accessible_endpoints[0], fake_fw,
            f"multipart/form-data; boundary={boundary}"
        )
        evidence["firmware_post_status"] = r_post.get("status")
        evidence["firmware_post_response"] = r_post.get("body_text", "")[:200]
        if r_post.get("status") not in (401, 403, None):
            evidence["update_endpoint_accepted_payload"] = True
        return {
            "vulnerable": None,
            "evidence": evidence,
            "detection_confidence": detection_confidence("B", evidence, "firmware_update_endpoint_probed"),
            "requires_manual_review": True,
        }

    r_root = probe.get("/")
    evidence["http_status"] = r_root.get("status")
    evidence["server_header"] = r_root.get("headers", {}).get("Server", "")
    evidence["update_endpoints_tested"] = update_endpoints

    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("C", evidence, "update_endpoints_not_found"),
        "requires_manual_review": True,
    }

class Poc28CVE202423922RCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-028"
    meta_poc_name = 'CVE-2024-23922 RCE Active Validation'
    meta_cve_id = 'CVE-2024-23922'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-23922'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-23922']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "28_Sony_XAV_AX5500_Firmware_Update_Verification_Audit") if "VULN" in dir() else "28_Sony_XAV_AX5500_Firmware_Update_Verification_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc28CVE202423922RCEAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

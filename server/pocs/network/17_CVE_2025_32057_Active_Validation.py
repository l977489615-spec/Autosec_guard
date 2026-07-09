#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import socket
import ssl
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 2,
    "cve": "CVE-2025-32057",
    "year": 2025,
    "domain": "IVI/CAN/OTA",
    "vendor_product": "Nissan Leaf ZE1 / Bosch Infotainment ECU",
    "component": "Linux IVI、RH850 CAN模块、Redbend OTA",
    "type": "证书校验缺失",
    "summary": "Redbend OTA/配置服务HTTPS未验证根证书，可能被伪造后端服务器。",
    "source_description": "The Infotainment ECU manufactured by Bosch which is installed in Nissan Leaf ZE1 – 2020 uses a Redbend service for over-the-air provisioning and updates. HTTPS is used for communication with the back-end server. Due to usage of the default configuration for the underlying SSL engine, the server root certificate is not verified. As a result, an attacker may be able to impersonate a Redbend backend server using a self-signed certificate.\n\n\n\nFirst identified on Nissan Leaf ZE1 manufactured in 2020.",
    "poc_status": "有公开BlackHat/PCA研究材料；未整理为一步式PoC",
    "research_value": "适合研究IVI到CAN边界突破、OTA信任链、域间横向移动。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-32057",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-32057",
        "https://www.nissan.co.uk/vehicles/new-vehicles/leaf.html",
        "http://i.blackhat.com/Asia-25/Asia-25-Evdokimov-Remote-Exploitation-of-Nissan-Leaf.pdf",
        "https://pcacybersecurity.com/resources/advisory/vulnerabilities-in-nissan-infotainment-manufactured-by-bosch",
        "https://cveawg.mitre.org/api/cve/CVE-2025-32057"
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
        "CVE-2025-32057",
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
        "manufactured",
        "which",
        "installed",
        "uses",
        "service",
        "over-the-air",
        "provisioning",
        "updates",
        "HTTPS",
        "used",
        "communication",
        "back-end",
        "server",
        "usage",
        "default",
        "configuration",
        "underlying"
    ]
}



def _run_poc(plugin) -> dict:
    """Probe CVE-2025-32057: check HTTPS certificate validation weakness on target OTA/IVI service."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    service_banner = params.get("service_banner", "")

    evidence = {
        "cve": "CVE-2025-32057",
        "target": target_ip,
        "technique": "Nissan Leaf ZE1 Bosch IVI HTTPS cert validation check - probe OTA backend endpoint without cert verification",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2025-32057",
    }

    vulnerable = None
    service_found = False

    for port in [443, 8443, 80]:
        try:
            ctx_unverified = ssl.create_default_context()
            ctx_unverified.check_hostname = False
            ctx_unverified.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target_ip, port), timeout=4) as raw_sock:
                with ctx_unverified.wrap_socket(raw_sock, server_hostname=target_ip) as tls_sock:
                    cert = tls_sock.getpeercert()
                    service_found = True
                    evidence["service_port"] = port
                    evidence["tls_version"] = tls_sock.version()
                    if cert:
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        evidence["cert_issuer"] = issuer.get("organizationName", "unknown")
                        cn = issuer.get("commonName", "")
                        evidence["cert_cn"] = cn
                        is_self_signed = issuer == dict(x[0] for x in cert.get("subject", []))
                        evidence["self_signed"] = is_self_signed
                        if is_self_signed:
                            vulnerable = True
                            evidence["note"] = "Self-signed certificate accepted - cert validation may be disabled"
                    break
        except ssl.SSLError as exc:
            evidence[f"ssl_error_port_{port}"] = str(exc)
        except Exception:
            pass

    if not service_found and service_banner:
        if any(kw in service_banner.lower() for kw in ["redbend", "ota", "nissan", "bosch"]):
            evidence["banner_match"] = True
            vulnerable = None

    if not service_found and vulnerable is None:
        evidence["note"] = "No HTTPS service found on target"
        vulnerable = False

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }

try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc17CVE202532057CertificateValidationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-002'
    meta_poc_name = 'CVE-2025-32057 证书校验缺失 Active Validation'
    meta_cve_id = 'CVE-2025-32057'
    meta_severity = 'Medium'
    meta_protocol = 'can'
    meta_target_os = ['linux']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-32057'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2025-32057']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "17_Nissan_Redbend_OTA_Certificate_Validation_Audit") if "VULN" in dir() else "17_Nissan_Redbend_OTA_Certificate_Validation_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc17CVE202532057CertificateValidationAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

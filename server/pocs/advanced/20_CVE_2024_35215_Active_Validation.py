#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import socket
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 29,
    "cve": "CVE-2024-35215",
    "year": 2024,
    "domain": "车载OS/QNX",
    "vendor_product": "BlackBerry QNX SDP",
    "component": "Networking Stack",
    "type": "空指针/DoS",
    "summary": "QNX SDP 7.1/7.0 IP socket options处理空指针，本地可DoS。",
    "source_description": "NULL pointer dereference in IP socket options processing of the Networking Stack in QNX Software Development Platform (SDP) version(s) 7.1 and 7.0 could allow an attacker with local access to cause a denial-of-service condition in the context of the Networking Stack process.",
    "poc_status": "未见公开PoC；供应商公告",
    "research_value": "QNX广泛用于IVI、ADAS和域控制器，属于车载基础软件风险。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-35215",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-35215",
        "https://support.blackberry.com/pkb/s/article/140162",
        "https://cveawg.mitre.org/api/cve/CVE-2024-35215"
    ],
    "affected": [
        {
            "vendor": "BlackBerry",
            "product": "QNX Software Development Platform (SDP)",
            "versions": [
                {
                    "version": "7.0",
                    "status": "affected",
                    "lessThanOrEqual": "7.1",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-35215",
        "BlackBerry",
        "QNX",
        "SDP",
        "Networking",
        "Stack",
        "DoS",
        "NULL",
        "pointer",
        "dereference",
        "socket",
        "options",
        "processing",
        "Software",
        "Development",
        "Platform",
        "could",
        "allow",
        "local",
        "access",
        "cause",
        "denial-of-service",
        "condition",
        "context",
        "process",
        "QNX Software Development Platform (SDP"
    ]
}


def _run_poc(plugin) -> dict:
    """Check QNX SDP version via SSH or software inventory for CVE-2024-35215."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    software_inventory = params.get("software_inventory_text", "")

    evidence = {
        "cve": "CVE-2024-35215",
        "target": target_ip,
        "technique": "QNX SDP version fingerprint via SSH or software inventory",
        "affected_versions": ["7.0", "7.1"],
        "reference": "https://support.blackberry.com/pkb/s/article/140162",
    }

    vulnerable = None

    if software_inventory:
        inv_lower = software_inventory.lower()
        if "qnx" in inv_lower:
            ver_match = re.search(r"qnx[^0-9]*(\d+\.\d+)", inv_lower)
            if ver_match:
                ver = ver_match.group(1)
                evidence["detected_version"] = ver
                try:
                    major, minor = ver.split(".")
                    fver = float(f"{major}.{minor}")
                    vulnerable = 7.0 <= fver <= 7.1
                except ValueError:
                    vulnerable = None
            else:
                evidence["note"] = "QNX found in inventory but version unclear"
                vulnerable = None
        else:
            evidence["note"] = "QNX not found in software inventory"
            vulnerable = False

    if vulnerable is None and target_ip and target_ip != "127.0.0.1":
        try:
            result = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "-o", "BatchMode=yes", f"root@{target_ip}",
                 "uname -a; pidin info 2>/dev/null | head -5"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout + result.stderr
            evidence["ssh_output"] = output[:500]
            if "qnx" in output.lower() or "photon" in output.lower():
                ver_match = re.search(r"(\d+\.\d+)", output)
                if ver_match:
                    ver = ver_match.group(1)
                    evidence["detected_version"] = ver
                    try:
                        fver = float(ver)
                        vulnerable = 7.0 <= fver <= 7.1
                    except ValueError:
                        vulnerable = None
        except Exception as exc:
            evidence["ssh_error"] = str(exc)

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

class Poc20CVE202435215NullDerefDoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-029'
    meta_poc_name = 'CVE-2024-35215 DoS Active Validation'
    meta_cve_id = 'CVE-2024-35215'
    meta_severity = 'High'
    meta_protocol = 'local'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-35215'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-35215']
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "20_QNX_Network_Stack_Null_Deref_DoS_Audit") if "VULN" in dir() else "20_QNX_Network_Stack_Null_Deref_DoS_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc20CVE202435215NullDerefDoSAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

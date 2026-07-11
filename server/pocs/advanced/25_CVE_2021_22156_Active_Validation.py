#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import socket
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 61,
    "cve": "CVE-2021-22156",
    "year": 2021,
    "domain": "车载OS/QNX",
    "vendor_product": "BlackBerry QNX SDP/OS for Safety",
    "component": "calloc() C runtime",
    "type": "整数溢出/RCE或DoS",
    "summary": "BadAlloc：QNX calloc整数溢出，可DoS或代码执行。",
    "source_description": "An integer overflow vulnerability in the calloc() function of the C runtime library of affected versions of BlackBerry® QNX Software Development Platform (SDP) version(s) 6.5.0SP1 and earlier, QNX OS for Medical 1.1 and earlier, and QNX OS for Safety 1.0.1 and earlier that could allow an attacker to potentially perform a denial of service or execute arbitrary code.",
    "poc_status": "有CISA/研究公告，未见通用车载PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-22156",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-22156",
        "https://support.blackberry.com/kb/articleDetail?articleNumber=000082334",
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-qnx-TOxjVPdL",
        "https://cveawg.mitre.org/api/cve/CVE-2021-22156"
    ],
    "affected": [
        {
            "vendor": "BlackBerry",
            "product": "QNX Software Development Platform (SDP), QNX OS for Medical and QNX OS for Safety",
            "versions": [
                {
                    "version": "QNX SDP 6.5.0 SP1 and earlier",
                    "status": "affected"
                },
                {
                    "version": "QNX OS for Medical 1.1 and earlier",
                    "status": "affected"
                },
                {
                    "version": "QNX OS for Safety 1.0.1 and earlier",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2021-22156",
        "BlackBerry",
        "QNX",
        "SDP",
        "Safety",
        "calloc",
        "runtime",
        "RCE",
        "DoS",
        "integer",
        "overflow",
        "vulnerability",
        "function",
        "library",
        "Software",
        "Development",
        "Platform",
        "earlier",
        "Medical",
        "could",
        "allow",
        "potentially",
        "perform",
        "denial",
        "service",
        "execute",
        "arbitrary",
        "code",
        "QNX Software Development Platform (SDP), QNX OS for Medical and QNX OS for Safety"
    ]
}


def _run_poc(plugin) -> dict:
    """Check QNX SDP version for CVE-2021-22156 (BadAlloc calloc integer overflow)."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    software_inventory = params.get("software_inventory_text", "")

    evidence = {
        "cve": "CVE-2021-22156",
        "target": target_ip,
        "technique": "QNX SDP version check - affected: SDP ≤6.5.0SP1, OS for Medical ≤1.1, OS for Safety ≤1.0.1",
        "reference": "https://support.blackberry.com/kb/articleDetail?articleNumber=000082334",
    }

    vulnerable = None

    if software_inventory:
        inv_lower = software_inventory.lower()
        if "qnx" in inv_lower:
            evidence["qnx_found"] = True
            ver_match = re.search(r"qnx[^0-9]*(\d+\.\d+)", inv_lower)
            if ver_match:
                ver = ver_match.group(1)
                evidence["detected_version"] = ver
                try:
                    fver = float(ver)
                    vulnerable = fver <= 6.5
                except ValueError:
                    vulnerable = None
            else:
                vulnerable = None
        else:
            evidence["note"] = "QNX not found in software inventory"
            vulnerable = False

    if vulnerable is None and target_ip and target_ip != "127.0.0.1":
        try:
            result = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "-o", "BatchMode=yes", f"root@{target_ip}",
                 "uname -r; pidin info 2>/dev/null | grep -i version | head -3"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout + result.stderr
            evidence["ssh_output"] = output[:400]
            if "qnx" in output.lower() or "neutrino" in output.lower():
                ver_match = re.search(r"(\d+\.\d+)", output)
                if ver_match:
                    ver = ver_match.group(1)
                    evidence["detected_version"] = ver
                    try:
                        fver = float(ver)
                        vulnerable = fver <= 6.5
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

class Poc25CVE202122156RCEDoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-ADV-025"
    meta_poc_name = 'CVE-2021-22156 RCE或DoS Active Validation'
    meta_cve_id = 'CVE-2021-22156'
    meta_severity = 'Critical'
    meta_protocol = 'local'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2021-22156'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2021-22156']
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "25_QNX_Calloc_Integer_Overflow_RCE_DoS_Audit") if "VULN" in dir() else "25_QNX_Calloc_Integer_Overflow_RCE_DoS_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc25CVE202122156RCEDoSAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

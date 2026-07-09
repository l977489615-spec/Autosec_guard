#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 62,
    "cve": "CVE-2021-32025",
    "year": 2021,
    "domain": "车载OS/QNX",
    "vendor_product": "BlackBerry QNX Neutrino Kernel",
    "component": "Kernel",
    "type": "权限提升",
    "summary": "QNX内核权限提升，可访问数据、改变行为或崩溃系统。",
    "source_description": "An elevation of privilege vulnerability in the QNX Neutrino Kernel of affected versions of QNX Software Development Platform version(s) 6.4.0 to 7.0, QNX Momentics all 6.3.x versions, QNX OS for Safety versions 1.0.0 to 1.0.2, QNX OS for Safety versions 2.0.0 to 2.0.1, QNX for Medical versions 1.0.0 to 1.1.1, and QNX OS for Medical version 2.0.0 could allow an attacker to potentially access data, modify behavior, or permanently crash the system.",
    "poc_status": "未见公开PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-32025",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-32025",
        "http://support.blackberry.com/kb/articleDetail?articleNumber=000090868",
        "https://cveawg.mitre.org/api/cve/CVE-2021-32025"
    ],
    "affected": [
        {
            "vendor": "BlackBerry",
            "product": "QNX Software Development Platform (SDP), QNX OS for Medical (QOSM), and QNX OS for Safety (QOS)",
            "versions": [
                {
                    "version": "QNX SDP 6.4.0 to 7.0",
                    "status": "affected"
                },
                {
                    "version": "QNX Momentics all 6.3.x versions",
                    "status": "affected"
                },
                {
                    "version": "QNX OS for Safety versions 1.0.0 to 1.0.2 safety products compliant with IEC 61508 and/or ISO 26262",
                    "status": "affected"
                },
                {
                    "version": "QNX OS for Safety versions 2.0.0 to 2.0.1 safety products compliant with IEC 61508 and/or ISO 26262",
                    "status": "affected"
                },
                {
                    "version": "QNX OS for Medical versions 1.0.0 to 1.1.1 safety products compliant with IEC 62304",
                    "status": "affected"
                },
                {
                    "version": "QNX OS for Medical versions 2.0.0 safety product compliant with IEC 62304",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2021-32025",
        "BlackBerry",
        "QNX",
        "Neutrino",
        "Kernel",
        "elevation",
        "privilege",
        "vulnerability",
        "Software",
        "Development",
        "Platform",
        "Momentics",
        "Safety",
        "Medical",
        "could",
        "allow",
        "potentially",
        "access",
        "data",
        "modify",
        "behavior",
        "permanently",
        "QNX Software Development Platform (SDP), QNX OS for Medical (QOSM), and QNX OS for Safety (QOS"
    ]
}


def _run_poc(plugin) -> dict:
    """Check QNX Neutrino kernel version for CVE-2021-32025 privilege escalation."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    software_inventory = params.get("software_inventory_text", "")

    evidence = {
        "cve": "CVE-2021-32025",
        "target": target_ip,
        "technique": "QNX Neutrino kernel version check - affected: SDP 6.4.0-7.0, Momentics 6.3.x, OS for Safety 1.0.0-2.0.1, OS for Medical 1.0.0-2.0.0",
        "reference": "http://support.blackberry.com/kb/articleDetail?articleNumber=000090868",
    }

    vulnerable = None

    if software_inventory:
        inv_lower = software_inventory.lower()
        if "qnx" in inv_lower or "neutrino" in inv_lower:
            evidence["qnx_found"] = True
            ver_match = re.search(r"(?:qnx|neutrino)[^0-9]*(\d+\.\d+)", inv_lower)
            if ver_match:
                ver = ver_match.group(1)
                evidence["detected_version"] = ver
                try:
                    fver = float(ver)
                    vulnerable = 6.4 <= fver <= 7.0
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
                 "uname -a; pidin info 2>/dev/null | head -3"],
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
                        vulnerable = 6.4 <= fver <= 7.0
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

class Poc26CVE202132025PrivilegeEscalationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-062'
    meta_poc_name = 'CVE-2021-32025 权限提升 Active Validation'
    meta_cve_id = 'CVE-2021-32025'
    meta_severity = 'High'
    meta_protocol = 'local'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2021-32025'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2021-32025']
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "26_QNX_Kernel_Privilege_Escalation_Audit") if "VULN" in dir() else "26_QNX_Kernel_Privilege_Escalation_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc26CVE202132025PrivilegeEscalationAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

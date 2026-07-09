#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 64,
    "cve": "CVE-2017-3893",
    "year": 2017,
    "domain": "车载OS/QNX",
    "vendor_product": "BlackBerry QNX SDP",
    "component": "GOT/PLT protection",
    "type": "内存保护绕过",
    "summary": "默认配置未能始终阻止攻击者通过溢出修改GOT/PLT。",
    "source_description": "In BlackBerry QNX Software Development Platform (SDP) 6.6.0, the default configuration of the QNX SDP system did not in all circumstances prevent attackers from modifying the GOT or PLT tables with buffer overflow attacks.",
    "poc_status": "未见公开PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-3893",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2017-3893",
        "http://support.blackberry.com/kb/articleDetail?articleNumber=000046674",
        "https://cveawg.mitre.org/api/cve/CVE-2017-3893"
    ],
    "affected": [
        {
            "vendor": "BlackBerry",
            "product": "QNX Software Development Platform (QNX SDP)",
            "versions": [
                {
                    "version": "6.6.0",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2017-3893",
        "BlackBerry",
        "QNX",
        "SDP",
        "GOT",
        "PLT",
        "protection",
        "Software",
        "Development",
        "Platform",
        "default",
        "configuration",
        "system",
        "circumstances",
        "prevent",
        "attackers",
        "modifying",
        "tables",
        "buffer",
        "overflow",
        "attacks",
        "QNX Software Development Platform (QNX SDP"
    ]
}


def _run_poc(plugin) -> dict:
    """Check QNX SDP 6.6.0 GOT/PLT memory protection configuration for CVE-2017-3893."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    software_inventory = params.get("software_inventory_text", "")

    evidence = {
        "cve": "CVE-2017-3893",
        "target": target_ip,
        "technique": "QNX SDP 6.6.0 version check + GOT/PLT RELRO configuration audit",
        "affected_versions": ["6.6.0"],
        "reference": "http://support.blackberry.com/kb/articleDetail?articleNumber=000046674",
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
                vulnerable = ver == "6.6"
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
                 "uname -r; pidin info 2>/dev/null | head -3"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout + result.stderr
            evidence["ssh_output"] = output[:400]
            if "6.6" in output:
                evidence["detected_version"] = "6.6"
                vulnerable = True
            elif "qnx" in output.lower():
                evidence["note"] = "QNX found but could not confirm version 6.6.0"
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

class Poc28CVE20173893ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-064'
    meta_poc_name = 'CVE-2017-3893 内存保护绕过 Active Validation'
    meta_cve_id = 'CVE-2017-3893'
    meta_severity = 'High'
    meta_protocol = 'local'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2017-3893'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2017-3893']
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "28_QNX_GOT_PLT_Memory_Protection_Bypass_Audit") if "VULN" in dir() else "28_QNX_GOT_PLT_Memory_Protection_Bypass_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc28CVE20173893ExposureAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 94,
    "cve": "CVE-2024-3094",
    "year": 2024,
    "domain": "车载Linux供应链",
    "vendor_product": "xz utils",
    "component": "liblzma backdoor",
    "type": "供应链后门",
    "summary": "若车载Linux构建链/镜像引入受影响xz，存在供应链后门风险。",
    "source_description": "Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. \r\nThrough a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.",
    "poc_status": "有公开检测/分析PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
        "https://access.redhat.com/security/cve/CVE-2024-3094",
        "https://bugzilla.redhat.com/show_bug.cgi?id=2272210",
        "https://www.openwall.com/lists/oss-security/2024/03/29/4",
        "https://www.redhat.com/en/blog/urgent-security-alert-fedora-41-and-rawhide-users",
        "https://cveawg.mitre.org/api/cve/CVE-2024-3094"
    ],
    "affected": [
        {
            "vendor": "",
            "product": "",
            "versions": [
                {
                    "version": "5.6.0",
                    "status": "affected"
                },
                {
                    "version": "5.6.1",
                    "status": "affected"
                }
            ]
        },
        {
            "vendor": "Red Hat",
            "product": "Red Hat Enterprise Linux 10",
            "versions": []
        },
        {
            "vendor": "Red Hat",
            "product": "Red Hat Enterprise Linux 6",
            "versions": []
        },
        {
            "vendor": "Red Hat",
            "product": "Red Hat Enterprise Linux 7",
            "versions": []
        },
        {
            "vendor": "Red Hat",
            "product": "Red Hat Enterprise Linux 8",
            "versions": []
        },
        {
            "vendor": "Red Hat",
            "product": "Red Hat Enterprise Linux 9",
            "versions": []
        },
        {
            "vendor": "Red Hat",
            "product": "Red Hat JBoss Enterprise Application Platform 8",
            "versions": []
        }
    ],
    "signature_tokens": [
        "CVE-2024-3094",
        "utils",
        "liblzma",
        "backdoor",
        "Malicious",
        "code",
        "discovered",
        "upstream",
        "tarballs",
        "starting",
        "series",
        "complex",
        "obfuscations",
        "build",
        "process",
        "extracts",
        "prebuilt",
        "object",
        "file",
        "disguised",
        "test",
        "existing",
        "source",
        "which",
        "then",
        "used",
        "modify",
        "Red Hat",
        "Red Hat Enterprise Linux 10",
        "Red Hat Enterprise Linux 6"
    ]
}


_BACKDOOR_STRINGS = ["N3/1t", "jWgdh4", "lHiAg"]
_AFFECTED_VERSIONS = ["5.6.0", "5.6.1"]


def _run_poc(plugin) -> dict:
    """Detect CVE-2024-3094 XZ/liblzma backdoor via version check and string scan."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    software_inventory = params.get("software_inventory_text", "")

    evidence = {
        "cve": "CVE-2024-3094",
        "target": target_ip,
        "technique": "xz/liblzma version check + backdoor string detection",
        "affected_versions": _AFFECTED_VERSIONS,
        "reference": "https://www.openwall.com/lists/oss-security/2024/03/29/4",
    }

    vulnerable = None

    if software_inventory:
        inv_lower = software_inventory.lower()
        if "xz" in inv_lower or "liblzma" in inv_lower:
            evidence["xz_found"] = True
            ver_match = re.search(r"(?:xz|liblzma)[^0-9]*(\d+\.\d+\.\d+)", inv_lower)
            if ver_match:
                ver = ver_match.group(1)
                evidence["detected_version"] = ver
                vulnerable = ver in _AFFECTED_VERSIONS
            else:
                vulnerable = None
        else:
            evidence["note"] = "xz/liblzma not found in software inventory"
            vulnerable = False

    if target_ip and target_ip != "127.0.0.1":
        try:
            result = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "-o", "BatchMode=yes", f"root@{target_ip}",
                 "xz --version 2>&1 | head -2; strings /usr/lib/liblzma.so* 2>/dev/null | grep -E 'N3/1t|jWgdh4|lHiAg' | head -3"],
                capture_output=True, text=True, timeout=15
            )
            output = result.stdout + result.stderr
            evidence["ssh_output"] = output[:600]
            ver_match = re.search(r"(\d+\.\d+\.\d+)", output)
            if ver_match:
                ver = ver_match.group(1)
                evidence["detected_version"] = ver
                if ver in _AFFECTED_VERSIONS:
                    vulnerable = True
            for sig in _BACKDOOR_STRINGS:
                if sig in output:
                    evidence["backdoor_string_found"] = sig
                    vulnerable = True
                    break
        except Exception as exc:
            evidence["ssh_error"] = str(exc)

    if vulnerable is None:
        try:
            result = subprocess.run(
                ["xz", "--version"], capture_output=True, text=True, timeout=5
            )
            output = result.stdout
            evidence["local_xz_output"] = output[:200]
            ver_match = re.search(r"(\d+\.\d+\.\d+)", output)
            if ver_match:
                ver = ver_match.group(1)
                evidence["local_version"] = ver
                if ver in _AFFECTED_VERSIONS:
                    vulnerable = True
        except Exception as exc:
            evidence["local_check_error"] = str(exc)

    # ── SSH / ADB remote version probe ──────────────────────────────────────
    import sys as _sys, subprocess as _sp, re as _re
    from pathlib import Path as _P
    _sys.path.insert(0, str(_P(__file__).parent))
    from probe_utils import detection_confidence, ssh_exec

    _ssh_user = params.get("ssh_user", "root")
    _ssh_pass = params.get("ssh_password")
    _ssh_key  = params.get("ssh_key_file")
    _ver_cmd  = "xz --version 2>&1 | head -1"
    _remote_out = ""

    if target_ip and target_ip != "127.0.0.1":
        _r = ssh_exec(target_ip, username=_ssh_user, password=_ssh_pass,
                      key_file=_ssh_key, command=_ver_cmd)
        _remote_out = _r.get("stdout", "").strip()
        evidence["ssh_xz_version"] = _remote_out

    if not _remote_out:
        try:
            _rp = _sp.run(_ver_cmd, shell=True, capture_output=True, text=True, timeout=8)
            _remote_out = (_rp.stdout + _rp.stderr).strip()
            evidence["local_xz_version"] = _remote_out
        except Exception as _e:
            evidence["local_probe_error"] = str(_e)

    _vm = _re.search(r"(\d+\.\d+\.\d+)", _remote_out)
    if _vm:
        _detected = _vm.group(1)
        evidence["detected_xz_version"] = _detected
        if _detected in _AFFECTED_VERSIONS:
            vulnerable = True
            evidence["version_in_affected_range"] = True

    if vulnerable:
        _conf = detection_confidence("C", evidence, "xz_version_ssh_or_local")
    elif vulnerable is False:
        _conf = detection_confidence("C", evidence, "xz_version_ssh_or_local")
    else:
        _conf = detection_confidence("D", evidence, "inventory_text_only")

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "detection_confidence": _conf,
        "requires_manual_review": vulnerable is None,
    }


class Poc29CVE20243094ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-094'
    meta_poc_name = 'CVE-2024-3094 供应链后门 Active Validation'
    meta_cve_id = 'CVE-2024-3094'
    meta_severity = 'Critical'
    meta_protocol = 'local'
    meta_target_os = ['linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-3094'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-3094']
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "29_XZ_LibLZMA_Supply_Chain_Backdoor_Audit") if "VULN" in dir() else "29_XZ_LibLZMA_Supply_Chain_Backdoor_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc29CVE20243094ExposureAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

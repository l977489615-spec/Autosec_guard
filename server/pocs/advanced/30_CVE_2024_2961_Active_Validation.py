#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import socket
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 100,
    "cve": "CVE-2024-2961",
    "year": 2024,
    "domain": "车载Linux依赖库",
    "vendor_product": "glibc iconv",
    "component": "ISO-2022-CN-EXT",
    "type": "缓冲区溢出",
    "summary": "车载Linux/IVI若使用glibc iconv解析文本可能受影响。",
    "source_description": "The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.",
    "poc_status": "有公开PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-2961",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-2961",
        "https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2024-0004",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/P3I4KYS6EU6S7QZ47WFNTPVAHFIUQNEL/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YAMJQI3Y6BHWV3CUTYBXOZONCUJNOB2Z/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BTJFBGHDYG5PEIFD5WSSSKSFZ2AZWC5N/",
        "http://www.openwall.com/lists/oss-security/2024/04/24/2",
        "http://www.openwall.com/lists/oss-security/2024/04/17/9",
        "http://www.openwall.com/lists/oss-security/2024/04/18/4",
        "https://lists.debian.org/debian-lts-announce/2024/05/msg00001.html",
        "http://www.openwall.com/lists/oss-security/2024/05/27/2",
        "http://www.openwall.com/lists/oss-security/2024/05/27/6",
        "https://cveawg.mitre.org/api/cve/CVE-2024-2961"
    ],
    "affected": [
        {
            "vendor": "The GNU C Library",
            "product": "glibc",
            "versions": [
                {
                    "version": "2.1.93",
                    "status": "affected",
                    "lessThan": "2.40",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-2961",
        "glibc",
        "iconv",
        "ISO-2022-CN-EXT",
        "function",
        "Library",
        "older",
        "overflow",
        "output",
        "buffer",
        "passed",
        "bytes",
        "when",
        "converting",
        "strings",
        "character",
        "which",
        "used",
        "crash",
        "application",
        "overwrite",
        "neighbouring",
        "variable",
        "The GNU C Library"
    ]
}


def _run_poc(plugin) -> dict:
    """Check glibc version for CVE-2024-2961 iconv ISO-2022-CN-EXT OOB write."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    software_inventory = params.get("software_inventory_text", "")

    evidence = {
        "cve": "CVE-2024-2961",
        "target": target_ip,
        "technique": "glibc version check - affected: glibc ≤2.39 (iconv ISO-2022-CN-EXT OOB write)",
        "reference": "https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2024-0004",
    }

    vulnerable = None

    if software_inventory:
        inv_lower = software_inventory.lower()
        if "glibc" in inv_lower or "libc" in inv_lower:
            evidence["glibc_found"] = True
            ver_match = re.search(r"glibc[^0-9]*(\d+\.\d+)", inv_lower)
            if ver_match:
                ver = ver_match.group(1)
                evidence["detected_version"] = ver
                try:
                    fver = float(ver)
                    vulnerable = fver <= 2.39
                except ValueError:
                    vulnerable = None
            else:
                vulnerable = None
        else:
            evidence["note"] = "glibc not explicitly found in software inventory"
            vulnerable = None

    if target_ip and target_ip != "127.0.0.1":
        try:
            result = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "-o", "BatchMode=yes", f"root@{target_ip}",
                 "ldd --version 2>&1 | head -2; getconf GNU_LIBC_VERSION 2>/dev/null"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout + result.stderr
            evidence["ssh_output"] = output[:400]
            ver_match = re.search(r"(\d+\.\d+)", output)
            if ver_match:
                ver = ver_match.group(1)
                evidence["detected_version"] = ver
                try:
                    fver = float(ver)
                    vulnerable = fver <= 2.39
                except ValueError:
                    vulnerable = None
        except Exception as exc:
            evidence["ssh_error"] = str(exc)

    if vulnerable is None:
        try:
            result = subprocess.run(
                ["ldd", "--version"], capture_output=True, text=True, timeout=5
            )
            output = result.stdout
            ver_match = re.search(r"(\d+\.\d+)", output)
            if ver_match:
                ver = ver_match.group(1)
                evidence["local_glibc_version"] = ver
                try:
                    fver = float(ver)
                    vulnerable = fver <= 2.39
                except ValueError:
                    pass
        except Exception as exc:
            evidence["local_check_error"] = str(exc)

    # ── SSH / Local remote version probe ────────────────────────────────────
    import sys as _sys, subprocess as _sp, re as _re
    from pathlib import Path as _P
    _sys.path.insert(0, str(_P(__file__).parent))
    from probe_utils import detection_confidence, ssh_exec, version_in_range

    _ssh_user = params.get("ssh_user", "root")
    _ssh_pass = params.get("ssh_password")
    _ssh_key  = params.get("ssh_key_file")
    _ver_cmd  = "ldd --version 2>&1 | head -1"
    _remote_out = ""

    if target_ip and target_ip != "127.0.0.1":
        _r = ssh_exec(target_ip, username=_ssh_user, password=_ssh_pass,
                      key_file=_ssh_key, command=_ver_cmd)
        _remote_out = _r.get("stdout", "").strip()
        evidence["ssh_glibc_version"] = _remote_out

    if not _remote_out:
        try:
            _rp = _sp.run(_ver_cmd, shell=True, capture_output=True, text=True, timeout=8)
            _remote_out = (_rp.stdout + _rp.stderr).strip()
            evidence["local_glibc_version"] = _remote_out
        except Exception as _e:
            evidence["local_probe_error"] = str(_e)

    _vm = _re.search(r"(\d+\.\d+)", _remote_out)
    if _vm:
        _detected = _vm.group(1)
        evidence["detected_glibc_version"] = _detected
        _in_range = version_in_range(_detected, lt="2.40")
        evidence["version_in_affected_range"] = _in_range
        if _in_range:
            vulnerable = True

    if vulnerable is True:
        _conf = detection_confidence("C", evidence, "glibc_version_ssh_or_local")
    elif vulnerable is False:
        _conf = detection_confidence("C", evidence, "glibc_version_ssh_or_local")
    else:
        _conf = detection_confidence("D", evidence, "inventory_text_only")

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "detection_confidence": _conf,
        "requires_manual_review": vulnerable is None,
    }


class Poc30CVE20242961ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-ADV-030"
    meta_poc_name = 'CVE-2024-2961 缓冲区溢出 Active Validation'
    meta_cve_id = 'CVE-2024-2961'
    meta_severity = 'High'
    meta_protocol = 'local'
    meta_target_os = ['linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-2961'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2024-2961']
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "30_Glibc_Iconv_Buffer_Overflow_Audit") if "VULN" in dir() else "30_Glibc_Iconv_Buffer_Overflow_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc30CVE20242961ExposureAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

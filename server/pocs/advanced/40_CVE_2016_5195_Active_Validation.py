#!/usr/bin/env python3
"""CVE-2016-5195 – DirtyCow: race condition in get_user_pages allows unprivileged write to read-onl.

Public PoC source: https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
  Files: []
  Technique: Race /proc/self/mem writes vs MAP_PRIVATE mmap + madvise(MADV_DONTNEED) to overwrite read-only file pages. Classic: write 'x' SSH key to root's authorized_keys or overwrite /etc/passwd root entry.

Reference: https://dirtycow.ninja/
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 40,
    "cve": "CVE-2016-5195",
    "year": 2016,
    "domain": "advanced",
    "vendor_product": "Linux kernel (IVI / AAOS / QNX coexistence host)",
    "component": "Linux kernel mm/gup.c – Copy-On-Write race condition",
    "type": "Local Privilege Escalation (LPE) → root",
    "summary": (
        "DirtyCow: race condition in get_user_pages allows unprivileged write to read-only memory-mapped files (e.g. /etc/passwd, /etc/shadow). Affects Linux kernels before 4.8.3 – nearly all IVI Linux builds."
    ),
    "source_url": "https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs",
    "requires_manual_review": True,
    "affected": [{"vendor": "Linux / Android",
                  "product": "Linux kernel (IVI / AAOS / QNX coexistence host)",
                  "versions": [{"version": "pre-patch", "status": "affected"}]}],
}

POC_REPO = Path(__file__).parent.parent.parent /     "public_poc_sources/repos/MISSING"


def _compile_and_run(allow_disruptive: bool, compile_cmd: str,
                     run_cmd: str, lab_cmd: str) -> dict:
    result = {}
    if not POC_REPO.exists():
        result["error"] = f"PoC repo not found at {POC_REPO}"
        return result

    if not allow_disruptive:
        result["would_compile"] = compile_cmd
        result["would_run"]     = run_cmd
        result["detail"] = "Set allow_disruptive=true to compile and run exploit."
        return result

    with tempfile.TemporaryDirectory() as tmpdir:
        # Copy repo contents to tmpdir
        import shutil as _shutil
        for f in POC_REPO.rglob("*"):
            if f.is_file():
                dest = Path(tmpdir) / f.relative_to(POC_REPO)
                dest.parent.mkdir(parents=True, exist_ok=True)
                _shutil.copy2(str(f), str(dest))

        # Compile
        if compile_cmd:
            r = subprocess.run(compile_cmd, shell=True, cwd=tmpdir,
                               capture_output=True, text=True, timeout=60)
            result["compile_rc"]  = r.returncode
            result["compile_out"] = (r.stdout + r.stderr)[:400]
            if r.returncode != 0:
                result["detail"] = "Compile failed – check gcc/make available on system."
                return result

        # Run
        if run_cmd:
            run_full = run_cmd
            if lab_cmd and lab_cmd != run_cmd:
                run_full = f"{run_cmd} && {lab_cmd}"
            r2 = subprocess.run(run_full, shell=True, cwd=tmpdir,
                                capture_output=True, text=True, timeout=120)
            result["run_rc"]   = r2.returncode
            result["run_out"]  = (r2.stdout + r2.stderr)[:400]
            result["exploited"] = ("root" in r2.stdout.lower() or
                                   "uid=0" in r2.stdout or
                                   "# " in r2.stdout)
    return result


def _check_version() -> dict:
    """Check if the local system appears vulnerable."""
    result = {}
    check_cmd = ''
    if check_cmd:
        try:
            r = subprocess.run(check_cmd, shell=True, capture_output=True,
                               text=True, timeout=10)
            result["check_out"] = (r.stdout + r.stderr)[:200]
        except Exception as exc:
            result["check_error"] = str(exc)
    return result


def _run_poc(plugin):
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))
    # Never accept a client-provided local command. The fixed identity probe is
    # sufficient to record the post-exploit privilege level.
    lab_cmd = "id"

    evidence = {
        "cve": "CVE-2016-5195",
        "poc_repo": str(POC_REPO),
        "poc_repo_present": POC_REPO.exists(),
        "exploit_files": [],
        "technique": (
            "Race /proc/self/mem writes vs MAP_PRIVATE mmap + madvise(MADV_DONTNEED) to overwrite read-only file pages. Classic: write 'x' SSH key to root's authorized_keys or overwrite /etc/passwd root entry."
        ),
        "reference": "https://dirtycow.ninja/",
    }

    ver = _check_version()
    evidence.update(ver)

    exploit = _compile_and_run(
        allow_disruptive,
        compile_cmd='',
        run_cmd='',
        lab_cmd=lab_cmd,
    )
    evidence.update(exploit)

    return {
        "vulnerable": evidence.get("exploited"),
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc40CVE20165195DirtyCowLinuxLpeAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50_more"
    meta_display_id = "POC-ADV-040"
    meta_poc_name   = 'CVE-2016-5195 Dirty COW Privilege Escalation Active Validation'
    meta_cve_id     = "CVE-2016-5195"
    meta_severity   = "Critical"
    meta_protocol   = "local"
    meta_target_os  = ["linux"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive", "lab_command"]
    meta_profiles   = ["advanced"]
    meta_source_url = "https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs"
    meta_references       = ['https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs']
    meta_attack_surface = "Race /proc/self/mem writes vs MAP_PRIVATE mmap + madvise(MADV_DONTNEED) to overw"
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

    _desc = VULN.get("summary", "40_DirtyCow_Linux_Kernel_LPE_Audit") if "VULN" in dir() else "40_DirtyCow_Linux_Kernel_LPE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc40CVE20165195DirtyCowLinuxLpeAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

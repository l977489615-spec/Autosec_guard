#!/usr/bin/env python3
"""CVE-2020-0041 – Android Binder p->buffer memory mismanagement vulnerability in alloc_free leadin.

Public PoC source: https://github.com/bluefrostsecurity/CVE-2020-0041
  Files: ['lpe/']
  Technique: Binder alloc_free OOB write via crafted ioctl sequence → overlap adjacent Binder buffers → overwrite task_struct creds → uid=0

Reference: https://labs.bluefrostsecurity.de/blog/2020/04/08/binder-vuln/
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 39,
    "cve": "CVE-2020-0041",
    "year": 2020,
    "domain": "advanced",
    "vendor_product": "Android (AAOS / IVI based on Android 9–10)",
    "component": "Linux Binder IPC driver – p->buffer memory management",
    "type": "Local Privilege Escalation (LPE) → root",
    "summary": (
        "Android Binder p->buffer memory mismanagement vulnerability in alloc_free leading to out-of-bounds write → kernel LPE/root. Exploit in bluefrostsecurity/CVE-2020-0041 (lpe/ directory)."
    ),
    "source_url": "https://github.com/bluefrostsecurity/CVE-2020-0041",
    "requires_manual_review": True,
    "affected": [{"vendor": "Linux / Android",
                  "product": "Android (AAOS / IVI based on Android 9–10)",
                  "versions": [{"version": "pre-patch", "status": "affected"}]}],
}

POC_REPO = Path(__file__).parent.parent.parent /     "public_poc_sources/repos/bluefrostsecurity__CVE-2020-0041"


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
    lab_cmd = (plugin.params or {}).get("lab_command", "id")

    evidence = {
        "cve": "CVE-2020-0041",
        "poc_repo": str(POC_REPO),
        "poc_repo_present": POC_REPO.exists(),
        "exploit_files": ['lpe/'],
        "technique": (
            "Binder alloc_free OOB write via crafted ioctl sequence → overlap adjacent Binder buffers → overwrite task_struct creds → uid=0"
        ),
        "reference": "https://labs.bluefrostsecurity.de/blog/2020/04/08/binder-vuln/",
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
        "poc_source": "https://github.com/bluefrostsecurity/CVE-2020-0041",
    }


class Poc39CVE20200041AndroidBinderLpeAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50_more"
    meta_display_id = "POC-ADV-039"
    meta_poc_name   = "CVE-2020-0041 Android Binder p->buffer memory mismanagement vulnerability in alloc_free leadin"
    meta_cve_id     = "CVE-2020-0041"
    meta_severity   = "Critical"
    meta_protocol   = "local"
    meta_target_os  = ["android"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive", "lab_command"]
    meta_profiles   = ["advanced"]
    meta_source_url = "https://github.com/bluefrostsecurity/CVE-2020-0041"
    meta_attack_surface = "Binder alloc_free OOB write via crafted ioctl sequence → overlap adjacent Binder"
    is_disruptive   = True
    meta_destructive_level = "RootCompromise"

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

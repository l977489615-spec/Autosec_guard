#!/usr/bin/env python3
"""CVE-2024-21626 – Leaky Vessels: runc leaks an internal O_CLOEXEC fd from /proc/self/fd into conta.

Public PoC source: https://github.com/NitroCao/CVE-2024-21626
  Files: ['README.md']
  Technique: runc sets up workdir via open(newroot/workdir, O_DIRECTORY|O_RDONLY) before closing internal fds. Container process iterates /proc/self/fd looking for fd with path /proc/self/fd/<n> → that fd points outside container → fchdir() + open('../../../etc/shadow') → host file read. With Dockerfile: WORKDIR /proc/self/fd/<n> → direct container escape.

Reference: https://snyk.io/blog/leaky-vessels-docker-runc-container-escape-vulnerabilities/
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 48,
    "cve": "CVE-2024-21626",
    "year": 2024,
    "domain": "advanced",
    "vendor_product": "runc <1.1.12 / containerd (IVI container runtime)",
    "component": "runc – leaked file descriptor in internal workdir",
    "type": "Local Privilege Escalation (LPE) → root",
    "summary": (
        "Leaky Vessels: runc leaks an internal O_CLOEXEC fd from /proc/self/fd into container process. Container process can traverse host root fs via the leaked fd → full host compromise via chdir + execve."
    ),
    "source_url": "https://github.com/NitroCao/CVE-2024-21626",
    "requires_manual_review": True,
    "affected": [{"vendor": "Linux / Android",
                  "product": "runc <1.1.12 / containerd (IVI container runtime)",
                  "versions": [{"version": "pre-patch", "status": "affected"}]}],
}

POC_REPO = Path(__file__).parent.parent.parent /     "public_poc_sources/repos/NitroCao__CVE-2024-21626"


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
    check_cmd = 'runc --version 2>&1'
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
        "cve": "CVE-2024-21626",
        "poc_repo": str(POC_REPO),
        "poc_repo_present": POC_REPO.exists(),
        "exploit_files": ['README.md'],
        "technique": (
            "runc sets up workdir via open(newroot/workdir, O_DIRECTORY|O_RDONLY) before closing internal fds. Container process iterates /proc/self/fd looking for fd with path /proc/self/fd/<n> → that fd points outside container → fchdir() + open('../../../etc/shadow') → host file read. With Dockerfile: WORKDIR /proc/self/fd/<n> → direct container escape."
        ),
        "reference": "https://snyk.io/blog/leaky-vessels-docker-runc-container-escape-vulnerabilities/",
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
        "poc_source": "https://github.com/NitroCao/CVE-2024-21626",
    }


class Poc48CVE20241086RuncContainerEscapeAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50_more"
    meta_display_id = "POC-ADV-048"
    meta_poc_name   = "CVE-2024-21626 Leaky Vessels: runc leaks an internal O_CLOEXEC fd from /proc/self/fd into conta"
    meta_cve_id     = "CVE-2024-21626"
    meta_severity   = "Critical"
    meta_protocol   = "local"
    meta_target_os  = ["linux"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive", "lab_command"]
    meta_profiles   = ["advanced"]
    meta_source_url = "https://github.com/NitroCao/CVE-2024-21626"
    meta_attack_surface = "runc sets up workdir via open(newroot/workdir, O_DIRECTORY|O_RDONLY) before clos"
    is_disruptive   = True
    meta_destructive_level = "RootCompromise"

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

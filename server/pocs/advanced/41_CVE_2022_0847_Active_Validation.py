#!/usr/bin/env python3
"""CVE-2022-0847 – DirtyPipe: uninitialized pipe_buffer.flags allows arbitrary file page cache over.

Public PoC source: https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit
  Files: ['exploit.c']
  Technique: Prepare PIPE_BUF_FLAG_CAN_MERGE on all pipe_buffer entries, then splice() target file page into pipe → write arbitrary bytes at any offset in target file. PoC overwrites /etc/passwd root hash.

Reference: https://dirtypipe.cm4all.com/
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 41,
    "cve": "CVE-2022-0847",
    "year": 2022,
    "domain": "advanced",
    "vendor_product": "Linux kernel 5.8+ (IVI built on mainline 5.x)",
    "component": "Linux kernel fs/pipe.c – uninitialized pipe_buffer.flags PIPE_BUF_FLAG_CAN_MERGE",
    "type": "Local Privilege Escalation (LPE) → root",
    "summary": (
        "DirtyPipe: uninitialized pipe_buffer.flags allows arbitrary file page cache overwrite even on read-only mounts. exploit.c by Max Kellermann (CM4all/IONOS) writes to any file in page cache. Affects kernel 5.8–5.16.10."
    ),
    "source_url": "https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit",
    "requires_manual_review": True,
    "affected": [{"vendor": "Linux / Android",
                  "product": "Linux kernel 5.8+ (IVI built on mainline 5.x)",
                  "versions": [{"version": "pre-patch", "status": "affected"}]}],
}

POC_REPO = Path(__file__).parent.parent.parent /     "public_poc_sources/repos/Arinerron__CVE-2022-0847-DirtyPipe-Exploit"


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
        "cve": "CVE-2022-0847",
        "poc_repo": str(POC_REPO),
        "poc_repo_present": POC_REPO.exists(),
        "exploit_files": ['exploit.c'],
        "technique": (
            "Prepare PIPE_BUF_FLAG_CAN_MERGE on all pipe_buffer entries, then splice() target file page into pipe → write arbitrary bytes at any offset in target file. PoC overwrites /etc/passwd root hash."
        ),
        "reference": "https://dirtypipe.cm4all.com/",
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
        "poc_source": "https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc41CVE20220847DirtyPipeLinuxKernelLpeAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50_more"
    meta_display_id = "POC-ADV-041"
    meta_poc_name   = 'CVE-2022-0847 Dirty Pipe Active Validation'
    meta_cve_id     = "CVE-2022-0847"
    meta_severity   = "Critical"
    meta_protocol   = "local"
    meta_target_os  = ["linux"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive", "lab_command"]
    meta_profiles   = ["advanced"]
    meta_source_url = "https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit"
    meta_references       = ['https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit']
    meta_attack_surface = "Prepare PIPE_BUF_FLAG_CAN_MERGE on all pipe_buffer entries, then splice() target"
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

    _desc = VULN.get("summary", "41_DirtyPipe_Linux_Kernel_LPE_Audit") if "VULN" in dir() else "41_DirtyPipe_Linux_Kernel_LPE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc41CVE20220847DirtyPipeLinuxKernelLpeAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

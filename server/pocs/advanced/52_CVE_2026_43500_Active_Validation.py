#!/usr/bin/env python3
"""CVE-2026-43500 – Dirty Frag (RxRPC/rxkad): splice() injects page cache into AF_RXRPC rxkad decryption path; missing COW guard allows arbitrary page cache write → /etc/passwd root entry overwrite or setuid binary page cache poisoning.

Public PoC source: https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-43500%20Dirty%20Frag
  Files: ['exploit/exp.c']  (combined chain with xfrm-ESP fallback)
  Technique (RxRPC/rxkad primary path):
    1. unshare(CLONE_NEWUSER|CLONE_NEWNET) to gain network namespace.
    2. Open AF_RXRPC socket with rxkad security class, bind/connect loopback.
    3. splice(/usr/bin/su → pipe → AF_RXRPC socket); rxkad decrypt path processes
       skb frag without COW → writes controlled bytes into page cache.
    4. Fallback: if /usr/bin/su immune, modify /etc/passwd root entry nullok → su -
  CVSS 3.1: 7.8 HIGH

Reference: https://nvd.nist.gov/vuln/detail/CVE-2026-43500
  Red Hat RHSB-2026-003: https://access.redhat.com/security/vulnerabilities/RHSB-2026-003
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 52,
    "cve": "CVE-2026-43500",
    "year": 2026,
    "domain": "advanced",
    "vendor_product": "Linux kernel (IVI/边缘 Linux 节点 with RxRPC)",
    "component": "Linux kernel net/rxrpc/ – rxkad decryption path missing COW guard on skb frag",
    "type": "本地权限提升 (LPE) → root / Page Cache 写入原语 / CVSS 7.8 HIGH",
    "summary": (
        "CVE-2026-43500 Dirty Frag RxRPC: splice() 把只读文件页缓存塞入 AF_RXRPC rxkad 解密路径，"
        "该路径缺少 COW 保护，在原地解密时写入页缓存，污染 /usr/bin/su 或修改 /etc/passwd → root。"
        "CVSS 7.8 HIGH；车载 Linux 节点（含 rxrpc.ko）需排查。"
    ),
    "source_url": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-43500%20Dirty%20Frag",
    "requires_manual_review": True,
    "affected": [
        {
            "vendor": "Linux",
            "product": "Linux kernel",
            "versions": [{"version": "any", "status": "affected", "lessThan": "patched"}],
        }
    ],
}

POC_REPO = (
    Path(__file__).parent.parent.parent
    / "public_poc_sources/repos/Unclecheng-li__poc-lab"
    / "CVE-2026-43500 Dirty Frag/exploit"
)


def _check_version() -> dict:
    result: dict = {}
    try:
        r = subprocess.run(["uname", "-r"], capture_output=True, text=True, timeout=5)
        result["kernel_version"] = r.stdout.strip()

        # Check rxrpc module
        lsmod = subprocess.run("lsmod", capture_output=True, text=True, timeout=5)
        result["rxrpc_loaded"] = "rxrpc" in lsmod.stdout
        # Try to probe-load rxrpc
        if not result["rxrpc_loaded"]:
            probe = subprocess.run(
                "modinfo rxrpc 2>/dev/null | head -3",
                shell=True, capture_output=True, text=True, timeout=5,
            )
            result["rxrpc_available_in_kernel"] = bool(probe.stdout.strip())
        else:
            result["rxrpc_available_in_kernel"] = True

        # Check user namespace
        userns = Path("/proc/sys/user/max_user_namespaces")
        result["user_namespace_max"] = userns.read_text().strip() if userns.exists() else "unknown"
        result["user_namespace_enabled"] = result["user_namespace_max"] not in ("0", "unknown")

        # Alibaba Cloud / Huawei kernels may ship without rxrpc; report accordingly
        vendor_info = ""
        os_release = Path("/etc/os-release")
        if os_release.exists():
            vendor_info = os_release.read_text()
        result["os_release_snippet"] = vendor_info[:200]

    except Exception as exc:
        result["check_error"] = str(exc)
    return result


def _compile_and_run(allow_disruptive: bool, lab_cmd: str) -> dict:
    result: dict = {}
    exp_c = POC_REPO / "exp.c"

    if not exp_c.exists():
        result["poc_repo_missing"] = str(POC_REPO)
        result["detail"] = (
            "Clone https://github.com/Unclecheng-li/poc-lab into "
            "public_poc_sources/repos/Unclecheng-li__poc-lab to enable compilation. "
            "PoC: gcc -O2 -o dirtyfrag-rxrpc exp.c && ./dirtyfrag-rxrpc"
        )
        result["would_compile"] = "gcc -O2 -o dirtyfrag-rxrpc exp.c"
        result["would_run"] = "./dirtyfrag-rxrpc"
        return result

    if not allow_disruptive:
        result["would_compile"] = "gcc -O2 -o dirtyfrag-rxrpc exp.c"
        result["would_run"] = "./dirtyfrag-rxrpc"
        result["detail"] = (
            "Set allow_disruptive=true to compile and run Dirty Frag RxRPC PoC. "
            "WARNING: May modify /etc/passwd or /usr/bin/su page cache. Isolated VM required."
        )
        return result

    with tempfile.TemporaryDirectory() as tmpdir:
        import shutil
        shutil.copy2(str(exp_c), f"{tmpdir}/exp.c")
        r = subprocess.run(
            "gcc -O2 -o dirtyfrag-rxrpc exp.c",
            shell=True, cwd=tmpdir, capture_output=True, text=True, timeout=60,
        )
        result["compile_rc"] = r.returncode
        result["compile_out"] = (r.stdout + r.stderr)[:400]
        if r.returncode != 0:
            result["detail"] = "Compile failed."
            return result

        r2 = subprocess.run(
            f"./dirtyfrag-rxrpc; {lab_cmd}",
            shell=True, cwd=tmpdir, capture_output=True, text=True, timeout=180,
        )
        result["run_rc"] = r2.returncode
        result["run_out"] = (r2.stdout + r2.stderr)[:600]
        result["exploited"] = (
            "uid=0" in r2.stdout
            or "root" in r2.stdout.lower()
            or "namespace_setup_complete" in r2.stdout
        )
    return result


def _run_poc(plugin) -> dict:
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))
    # Never accept a client-provided local command. The fixed identity probe is
    # sufficient to record the post-exploit privilege level.
    lab_cmd = "id"

    evidence: dict = {
        "cve": "CVE-2026-43500",
        "poc_repo": str(POC_REPO),
        "poc_repo_present": (POC_REPO / "exp.c").exists(),
        "exploit_files": ["exploit/exp.c"],
        "technique": (
            "unshare NEWUSER+NEWNET → AF_RXRPC + rxkad loopback handshake "
            "→ splice(/usr/bin/su → pipe → rxrpc socket) "
            "→ rxkad in-place decrypt without COW → page cache write "
            "→ fallback: /etc/passwd nullok patch → su - → root (CVSS 7.8)."
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-43500",
        "rhel_advisory": "https://access.redhat.com/security/vulnerabilities/RHSB-2026-003",
    }

    ver = _check_version()
    evidence.update(ver)
    exploit = _compile_and_run(allow_disruptive, lab_cmd)
    evidence.update(exploit)

    return {
        "vulnerable": evidence.get("exploited"),
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-43500%20Dirty%20Frag",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc52CVE202643500DirtyFragRxRPCLpeAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "poc_lab_vehicle"
    meta_display_id = "POC-ADV-052"
    meta_poc_name = 'CVE-2026-43500 Dirty Frag RxRPC Privilege Escalation Active Validation'
    meta_cve_id = "CVE-2026-43500"
    meta_severity = "High"
    meta_protocol = "local"
    meta_target_os = ["linux"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive", "lab_command"]
    meta_profiles = ["advanced", "kernel", "pagecache", "rxrpc"]
    meta_source_url = "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-43500%20Dirty%20Frag"
    meta_references       = ['https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-43500%20Dirty%20Frag']
    meta_attack_surface = (
        "本地用户通过 AF_RXRPC rxkad 解密路径污染 setuid 二进制 page cache 或 /etc/passwd → root"
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

    _desc = VULN.get("summary", "52_Linux_Kernel_DirtyFrag_RxRPC_LPE_Audit") if "VULN" in dir() else "52_Linux_Kernel_DirtyFrag_RxRPC_LPE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc52CVE202643500DirtyFragRxRPCLpeAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

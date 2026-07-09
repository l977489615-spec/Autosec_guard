#!/usr/bin/env python3
"""
PoC Name  : 检测设备是否启用安全SELinux状态...
CVE       : CWE-284
Category  : advanced
Severity  : Medium
Type      : Type-A
Description: 检测设备是否启用安全SELinux状态... vulnerability detection.
Prerequisites: See HW_REQUIREMENTS or VULN dict for details.
Usage     : python3 10_CWE_284_SELinux_Policy_Active_Validation.py <target_ip>
"""

from __future__ import annotations
POC_TAG = "6. 检测设备是否启用安全SELinux状态..."


from typing import List, Optional, Tuple
import subprocess
import logging
import re
import sys
import argparse

# logging 配置
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

ADB_CMD = "adb"
CMD_TIMEOUT = 4.0


def run_cmd_try_enc(cmd: List[str], timeout: float = CMD_TIMEOUT) -> Tuple[int, str]:
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout)
        try:
            out = proc.stdout.decode("utf-8", errors="ignore")
        except Exception:
            try:
                out = proc.stdout.decode("gbk", errors="ignore")
            except Exception:
                out = proc.stdout.decode("utf-8", errors="ignore")
        if not out:
            try:
                out = proc.stderr.decode("utf-8", errors="ignore")
            except Exception:
                out = proc.stderr.decode("gbk", errors="ignore")
        return proc.returncode, (out or "").strip()
    except subprocess.TimeoutExpired:
        return -1, ""
    except FileNotFoundError as e:
        return -2, str(e)
    except Exception as e:
        return -3, str(e)


def list_adb_devices() -> List[str]:
    code, out = run_cmd_try_enc([ADB_CMD, "devices"], timeout=3.0)
    devices = []
    if code < 0 or not out:
        return devices
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln or ln.lower().startswith("list of devices"):
            continue
        parts = ln.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


def adb_shell(device: Optional[str], shell_cmd: str) -> Tuple[int, str]:
    cmd = [ADB_CMD]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", shell_cmd]
    return run_cmd_try_enc(cmd, timeout=CMD_TIMEOUT)


def check_getenforce(device: str) -> Tuple[bool, str]:
    code, out = adb_shell(device, "getenforce")
    if code < 0 or not out:
        return False, ""
    normalized = out.strip()
    return True, normalized


def check_sys_enforce(device: str) -> Tuple[bool, Optional[int]]:
    code, out = adb_shell(device, "cat /sys/fs/selinux/enforce 2>/dev/null || true")
    if code < 0 or not out:
        return False, None
    # 找第一个数字 0 或 1
    m = re.search(r"\b([01])\b", out)
    if m:
        return True, int(m.group(1))
    return True, None


def check_getprop(device: str) -> Tuple[bool, str]:
    props = [
        "ro.boot.selinux",
        "ro.build.selinux",
        "init.svc.selinux"
    ]
    gathered = []
    for p in props:
        code, out = adb_shell(device, f"getprop {p} 2>/dev/null || true")
        if code >= 0 and out:
            gathered.append(f"{p}={out.strip()}")
    return (len(gathered) > 0), "; ".join(gathered)


def analyze_device(device: str) -> dict:
    result = {
        "device": device,
        "getenforce_ok": False,
        "getenforce": None,
        "sys_enforce_ok": False,
        "sys_enforce": None,
        "getprop_ok": False,
        "getprop": None,
        "vulnerable": None,
        "notes": []
    }

    gi_ok, gi_out = check_getenforce(device)
    result["getenforce_ok"] = gi_ok
    result["getenforce"] = gi_out
    if gi_ok and gi_out:
        norm = gi_out.lower()
        if "enforcing" in norm:
            result["notes"].append("getenforce reports Enforcing")
        elif "permissive" in norm:
            result["notes"].append("getenforce reports Permissive")
        else:
            result["notes"].append(f"getenforce returned: {gi_out}")

    se_ok, se_val = check_sys_enforce(device)
    result["sys_enforce_ok"] = se_ok
    result["sys_enforce"] = se_val
    if se_ok:
        if se_val == 1:
            result["notes"].append("/sys/fs/selinux/enforce is 1")
        elif se_val == 0:
            result["notes"].append("/sys/fs/selinux/enforce is 0")
        else:
            result["notes"].append("/sys/fs/selinux/enforce exists but content not 0/1")

    gp_ok, gp_out = check_getprop(device)
    result["getprop_ok"] = gp_ok
    result["getprop"] = gp_out
    if gp_ok and gp_out:
        result["notes"].append(f"getprop: {gp_out}")

    # 决策逻辑
    # 如果 getenforce 成功且明确为 permissive 则 vulnerable True
    if gi_ok and gi_out:
        if "permissive" in gi_out.lower():
            result["vulnerable"] = True
            return result
        if "enforcing" in gi_out.lower():
            # 如果 getenforce=enforcing 但 /sys/fs/selinux/enforce==0 则视为异常并 vulnerable True
            if se_ok and se_val == 0:
                result["vulnerable"] = True
                result["notes"].append("getenforce says Enforcing but /sys/fs/selinux/enforce is 0")
                return result
            result["vulnerable"] = False
            return result

    # 若 getenforce 不可用 但 /sys/fs/selinux/enforce 可读
    if se_ok and se_val is not None:
        if se_val == 0:
            result["vulnerable"] = True
            return result
        if se_val == 1:
            result["vulnerable"] = False
            return result

    # 最后退化判断
    # 若 getprop 显示相关属性指示 permissive 或空缺 则标记为可能 vulnerable 否则未知
    if gp_ok and gp_out:
        low = gp_out.lower()
        if "permissive" in low or "disabled" in low or "0" in low:
            result["vulnerable"] = True
            return result

    # 无法确定
    result["vulnerable"] = None
    result["notes"].append("could not determine SELinux state reliably")
    return result


def summarize(results: List[dict]) -> None:
    flag = False
    for r in results:
        dev = r.get("device")
        vul = r.get("vulnerable")
        if vul is True:
            logging.warning(f"{dev} SELinux is permissive or disabled. Vulnerable")
            for n in r.get("notes", []):
                logging.warning(f"{dev} note: {n}")
        elif vul is False:
            logging.warning(f"{dev} SELinux is enforcing. Not vulnerable")
            flag = True
            for n in r.get("notes", []):
                logging.warning(f"{dev} note: {n}")
        else:
            logging.warning(f"{dev} SELinux state unknown")
            for n in r.get("notes", []):
                logging.warning(f"{dev} note: {n}")
    return flag

def run_check() -> None:
    parser = argparse.ArgumentParser(description="检测已连接 Android 设备的 SELinux 状态")
    parser.add_argument("--serial", help="指定设备序列号 可选 若不指定脚本会扫描所有 adb devices 列表中的设备")
    args = parser.parse_args()

    devices = []
    if args.serial:
        devices = [args.serial]
    else:
        devices = list_adb_devices()
    if not devices:
        logging.warning("no adb devices found. ensure adb is connected and device is online")
        sys.exit(0)

    results = []
    for dev in devices:
        logging.warning(f"checking device {dev}")
        res = analyze_device(dev)
        results.append(res)

    return summarize(results)




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
        "check": 'SELinux disabled or in permissive mode',
        "target": target_ip or "local",
        "technique": "SSH remote command execution + output analysis",
    }

    cmd = 'getenforce 2>/dev/null || cat /sys/fs/selinux/enforce 2>/dev/null || echo UNKNOWN'
    vuln_pattern = 'Disabled|Permissive'

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


class Poc6SelinuxPlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-ADV-010"
    meta_poc_name = 'CWE-284 SELinux Policy Active Validation'
    meta_cve_id = 'CWE-284'
    meta_source_url = 'https://cwe.mitre.org/data/definitions/284.html'
    meta_references = ['https://cwe.mitre.org/data/definitions/284.html']
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

    _desc = VULN.get("summary", "10_SELinux_Policy_Audit") if "VULN" in dir() else "10_SELinux_Policy_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc6SelinuxPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

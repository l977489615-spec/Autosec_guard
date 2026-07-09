#!/usr/bin/env python3
"""
PoC Name  : 检测已连接的 Android 设备上若干敏感文件或接口的权限问题...
CVE       : CWE-732
Category  : advanced
Severity  : Medium
Type      : Type-B
Description: 检测已连接的 Android 设备上若干敏感文件或接口的权限问题... vulnerability detection.
Prerequisites: See HW_REQUIREMENTS or VULN dict for details.
Usage     : python3 09_CWE_732_File_ACL_Permission_Active_Validation.py <target_ip>
"""

from __future__ import annotations
POC_TAG = "5. 检测已连接的 Android 设备上若干敏感文件或接口的权限问题..."


import argparse
import logging
import re
import subprocess
import sys
from typing import List, Optional, Tuple

# logging 配置 使用统一格式
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

ADB_CMD = "adb"

# 要检查的路径列表
CHECK_PATHS = [
    "/data/system/users/0/accounts.db",
    "/data/system/locksettings.db",
    "/data/misc/wifi/wpa_supplicant.conf",
    "/data/system/packages.xml",
    "/proc/kmsg"
]

# 超时时间 较短即可
CMD_TIMEOUT = 4.0


def run_cmd_try_enc(cmd: List[str], timeout: float = CMD_TIMEOUT) -> Tuple[int, str]:
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout)
        # 优先尝试 utf-8
        try:
            out = proc.stdout.decode("utf-8", errors="ignore")
        except Exception:
            try:
                out = proc.stdout.decode("gbk", errors="ignore")
            except Exception:
                out = proc.stdout.decode("utf-8", errors="ignore")
        # 若无 stdout 则用 stderr
        if not out:
            try:
                out = proc.stderr.decode("utf-8", errors="ignore")
            except Exception:
                out = proc.stderr.decode("gbk", errors="ignore")
        return proc.returncode, out or ""
    except subprocess.TimeoutExpired:
        return -1, ""
    except FileNotFoundError as e:
        return -2, str(e)
    except Exception as e:
        return -3, str(e)


def list_adb_devices() -> List[str]:
    code, out = run_cmd_try_enc([ADB_CMD, "devices"], timeout=3.0)
    devices: List[str] = []
    if code < 0 or not out:
        return devices
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("List of devices"):
            continue
        parts = ln.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


def adb_ls(device: Optional[str], path: str) -> Tuple[int, str]:
    cmd = [ADB_CMD]
    if device:
        cmd += ["-s", device]
    # 使用 -l 以获取权限字符串 以及尽量不因中文系统乱码影响 输出放入 try 解码
    cmd += ["shell", "ls", "-l", path]
    return run_cmd_try_enc(cmd, timeout=5.0)


LS_REGEX = re.compile(r'^([\-ldsbcp]{1}[rwx\-]{9})\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$')


def parse_ls_line(line: str) -> Optional[Tuple[str, str]]:
    m = LS_REGEX.match(line.strip())
    if m:
        perm = m.group(1)
        name = m.group(2).strip()
        return perm, name
    return None


def other_writable_or_executable(perm: str) -> Tuple[bool, bool]:
    if not perm or len(perm) < 10:
        return False, False
    other = perm[-3:]
    return ('w' in other), ('x' in other)


def check_path_on_device(device: str, path: str) -> dict:
    code, out = adb_ls(device, path)
    entry = {
        "device": device,
        "path": path,
        "exists": False,
        "perm": None,
        "name": None,
        "other_writable": False,
        "other_executable": False,
        "raw": out.strip()[:1000]
    }
    if code < 0:
        # adb 命令问题 或超时 等
        entry["note"] = f"adb ls command failed returncode {code}"
        return entry
    if not out:
        entry["note"] = "no output from ls"
        return entry
    # ls -l 在文件存在时通常返回一行 权限等信息
    # 但当文件不存在时 ls 会输出 like: ls: /path: No such file or directory
    if "No such file" in out or "没有那个文件或目录" in out:
        entry["exists"] = False
        entry["note"] = "not found"
        return entry
    # 解析可能的多行 输出 找到首个匹配行
    for ln in out.splitlines():
        parsed = parse_ls_line(ln)
        if parsed:
            perm, name = parsed
            entry["exists"] = True
            entry["perm"] = perm
            entry["name"] = name
            owrite, oxec = other_writable_or_executable(perm)
            entry["other_writable"] = owrite
            entry["other_executable"] = oxec
            return entry
    # 若未匹配到 ls 格式 行 将原始输出作为提示 仍标记存在以便人工判断
    entry["exists"] = True
    entry["note"] = "could not parse ls output"
    return entry


def summarize_and_warn(results: List[dict]):
    flag = False
    for r in results:
        dev = r.get("device")
        path = r.get("path")
        if not r.get("exists"):
            logging.warning(f"{dev} {path} not found or inaccessible")
            continue
        perm = r.get("perm") or ""
        name = r.get("name") or path
        owrite = r.get("other_writable", False)
        oxec = r.get("other_executable", False)
        # 若 other 写 或 可执行 则视为高风险
        if owrite or oxec:
            logging.warning(f"{dev} HIGH RISK {path} perm={perm} name={name} other_write={owrite} other_exec={oxec}")
            flag = True
        else:
            logging.warning(f"{dev} OK {path} perm={perm} name={name}")

    return flag


def run_check() -> None:
    parser = argparse.ArgumentParser(description="检测已连接 Android 设备上的敏感文件权限")
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

    all_results = []
    for dev in devices:
        logging.warning(f"checking device {dev}")
        for p in CHECK_PATHS:
            res = check_path_on_device(dev, p)
            all_results.append(res)

    return summarize_and_warn(all_results)




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
        "check": 'world-writable or wrong permissions on sensitive files',
        "target": target_ip or "local",
        "technique": "SSH remote command execution + output analysis",
    }

    cmd = 'ls -la /etc/passwd /etc/shadow /etc/sudoers 2>&1'
    vuln_pattern = 'world-writable'

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



# ── 硬件需求（HW_REQUIREMENTS） ────────────────────────────────────────
HW_REQUIREMENTS = {
    "hardware":   ['USB Bluetooth 适配器（Ubertooth One 推荐用于嗅探）', '或内置 HCI 的 Linux 主机'],
    "connection": 'HCI（/dev/hci0）或 USB（Ubertooth）',
    "tools":      ['BlueZ ≥ 5.48', 'Ubertooth 工具链', 'Wireshark + BT 插件'],
    "firmware":   'Ubertooth firmware 2020-12-R1（ubertooth-dfu）',
    "setup":      'ubertooth-util -v && hciconfig hci0 up',
}

class Poc5FileaclPlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-ADV-009"
    meta_poc_name = 'CWE-732 File ACL Permission Active Validation'
    meta_cve_id = 'CWE-732'
    meta_source_url = 'https://cwe.mitre.org/data/definitions/732.html'
    meta_references = ['https://cwe.mitre.org/data/definitions/732.html']
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

    _desc = VULN.get("summary", "09_File_ACL_Permission_Audit") if "VULN" in dir() else "09_File_ACL_Permission_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc5FileaclPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

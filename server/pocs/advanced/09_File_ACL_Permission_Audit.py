#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检测已连接的 Android 设备上若干敏感文件或接口的权限问题...
"""
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
    """
    运行外部命令 并返回 (returncode, output_str)
    先以 utf-8 解码 若失败再尝试 gbk 解码 以兼容 Windows 平台
    保证返回字符串 不返回 None
    """
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
    """
    解析 adb devices 输出 返回在线设备序列号列表
    包含 ip:port 形式和普通序列号
    """
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
    """
    在设备上执行 ls -l 路径 并返回 (returncode, output)
    device 为 None 表示使用默认设备 否则传入 -s device
    """
    cmd = [ADB_CMD]
    if device:
        cmd += ["-s", device]
    # 使用 -l 以获取权限字符串 以及尽量不因中文系统乱码影响 输出放入 try 解码
    cmd += ["shell", "ls", "-l", path]
    return run_cmd_try_enc(cmd, timeout=5.0)


LS_REGEX = re.compile(r'^([\-ldsbcp]{1}[rwx\-]{9})\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$')


def parse_ls_line(line: str) -> Optional[Tuple[str, str]]:
    """
    解析单行 ls -l 输出 返回 (perm_str, filename) 或 None
    例如:
    -rw-rw-r-- 1 u0_a123 u0_a123 12345 2025-01-01  foo.db
    """
    m = LS_REGEX.match(line.strip())
    if m:
        perm = m.group(1)
        name = m.group(2).strip()
        return perm, name
    return None


def other_writable_or_executable(perm: str) -> Tuple[bool, bool]:
    """
    判断权限字符串中 other 部分 是否具有写或执行 权限
    perm 例如: -rw-rw-r--
    返回 (other_writable, other_executable)
    """
    if not perm or len(perm) < 10:
        return False, False
    other = perm[-3:]
    return ('w' in other), ('x' in other)


def check_path_on_device(device: str, path: str) -> dict:
    """
    检查单个路径 在目标设备上的情况
    返回字典形式的检测条目
    """
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
    """
    对检测结果进行汇总 并使用 logging.warning 输出高风险项提示
    """
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


class Poc5FileaclPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测已连接的 Android 设备上若干敏感文件或接口的权限问题...'
    meta_cve_id = 'CWE-732'
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

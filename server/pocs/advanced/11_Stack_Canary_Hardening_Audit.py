#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检测已连接设备是否启用栈保护机制...
检测已连接安卓设备上若干 so 文件是否包含栈保护相关符号（例如 __stack_chk_fail）
前提: 假定 adb 服务已连接且设备已在 adb devices 列表中


"""
POC_TAG = "7. 检测已连接设备是否启用栈保护机制..."

import argparse
import logging
import os
import subprocess
import sys
import tempfile
import time
from typing import List, Optional, Tuple

# logging 配置
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

ADB_CMD = "adb"
CMD_TIMEOUT = 8.0

# 默认要检查的 so 列表（可通过 --libs 覆盖）
DEFAULT_LIBS = [
    "/system/lib/libc.so",
    "/system/lib/libm.so",
    "/system/lib/libcrypto.so"
]

# 要搜索的符号（常见的 stack protector 相关符号）
CHECK_SYMBOLS = ["__stack_chk_fail", "__stack_chk_guard", "__stack_chk_fail_local"]


def run_cmd_try_enc(cmd: List[str], timeout: float = CMD_TIMEOUT) -> Tuple[int, str]:
    """运行外部命令并返回 (returncode, stdout_or_stderr)"""
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout)
        out = b""
        if proc.stdout:
            out = proc.stdout
        elif proc.stderr:
            out = proc.stderr
        try:
            text = out.decode("utf-8", errors="ignore")
        except Exception:
            text = out.decode("gbk", errors="ignore")
        return proc.returncode, text.strip()
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
    return run_cmd_try_enc(cmd, timeout=6.0)


def adb_pull(device: Optional[str], remote_path: str, local_path: str) -> Tuple[int, str]:
    cmd = [ADB_CMD]
    if device:
        cmd += ["-s", device]
    cmd += ["pull", remote_path, local_path]
    return run_cmd_try_enc(cmd, timeout=15.0)


def tool_available(name: str) -> bool:
    code, _ = run_cmd_try_enc([name, "--version"], timeout=2.0)
    return code >= 0


def analyze_file_symbols_local(filepath: str, symbols: List[str]) -> dict:
    """
    在本机对已拉下的 so 文件分析符号
    优先使用 readelf -s, 然后 nm -D, 然后 strings
    返回字典 { 'method': 'readelf'|'nm'|'strings'|'none', 'found': {symbol: bool, ...}, 'note': str }
    """
    result = {"method": None, "found": {}, "note": ""}
    for s in symbols:
        result["found"][s] = False

    # 1. readelf -s
    if tool_available("readelf"):
        code, out = run_cmd_try_enc(["readelf", "-s", filepath], timeout=10.0)
        result["method"] = "readelf"
        if code >= 0 and out:
            lo = out.lower()
            for sym in symbols:
                if sym.lower() in lo:
                    result["found"][sym] = True
        else:
            result["note"] = f"readelf failed code={code}"
        return result

    # 2. nm -D
    if tool_available("nm"):
        code, out = run_cmd_try_enc(["nm", "-D", filepath], timeout=10.0)
        result["method"] = "nm"
        if code >= 0 and out:
            lo = out.lower()
            for sym in symbols:
                if sym.lower() in lo:
                    result["found"][sym] = True
        else:
            result["note"] = f"nm failed code={code}"
        return result

    # 3. strings
    if tool_available("strings"):
        code, out = run_cmd_try_enc(["strings", filepath], timeout=8.0)
        result["method"] = "strings"
        if code >= 0 and out:
            lo = out.lower()
            for sym in symbols:
                if sym.lower() in lo:
                    result["found"][sym] = True
        else:
            result["note"] = "strings failed"
        return result

    result["method"] = "none"
    result["note"] = "no readelf/nm/strings available on host"
    return result


def check_so_on_device(device: str, remote_path: str, tmpdir: str) -> dict:
    """
    检查单个设备上的单个 so：
    1. 判断文件是否存在 (adb shell ls)
    2. 若存在，adb pull 到临时目录
    3. 在本地分析符号
    返回结果 dict
    """
    r = {"device": device, "remote_path": remote_path, "exists": False, "analysis": None, "note": ""}

    # 检查是否存在
    code, out = adb_shell(device, f"ls {remote_path} 2>/dev/null || true")
    if code < 0 or not out:
        r["note"] = "ls returned empty or failed"
        return r
    if "No such file" in out or "没有那个文件或目录" in out:
        r["exists"] = False
        r["note"] = "not found"
        return r
    # assume exists
    r["exists"] = True

    # pull file
    base = os.path.basename(remote_path)
    local_path = os.path.join(tmpdir, f"{device.replace(':', '_')}_{base}")
    codep, outp = adb_pull(device, remote_path, local_path)
    if codep < 0 or not os.path.exists(local_path):
        r["note"] = f"pull failed or file missing locally: code={codep} out={outp[:200]}"
        return r

    # analyze local file
    analysis = analyze_file_symbols_local(local_path, CHECK_SYMBOLS)
    r["analysis"] = analysis

    # cleanup local file to save space
    try:
        os.remove(local_path)
    except Exception:
        pass

    return r


def run_check():
    parser = argparse.ArgumentParser(description="检测设备上指定 so 是否包含栈保护符号")
    parser.add_argument("--libs", nargs="+", default=DEFAULT_LIBS,
                        help="要检查的 so 路径 列表")
    parser.add_argument("--serial", help="指定设备序列号 可选 若不指定则扫描所有 adb devices")
    args = parser.parse_args()

    devices = [args.serial] if args.serial else list_adb_devices()
    if not devices:
        logging.warning("no adb devices found. ensure adb is connected and device is online")
        sys.exit(0)

    tmpdir = tempfile.mkdtemp(prefix="so_check_")
    results = []
    flag = False
    for dev in devices:
        logging.warning(f"checking device {dev}")
        for lib in args.libs:
            logging.warning(f"  checking {lib} ...")
            res = check_so_on_device(dev, lib, tmpdir)
            results.append(res)
            # 输出结果摘要
            if not res["exists"]:
                logging.warning(f"    {lib} not found on {dev}")
            else:
                method = res["analysis"]["method"] if res.get("analysis") else "none"
                found_syms = [s for s, v in (res.get("analysis", {}).get("found", {}) or {}).items() if v]
                if found_syms:
                    logging.warning(f"    {lib} on {dev} contains symbols {found_syms} (analysis via {method})")
                    flag = True
                else:
                    logging.warning(f"    {lib} on {dev} does not contain target symbols (analysis via {method})")

    # remove tmpdir
    try:
        os.rmdir(tmpdir)
    except Exception:
        pass

    return flag

    # logging.warning("stack protector check complete")



# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc7StackchkPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测已连接设备是否启用栈保护机制...'
    meta_cve_id = 'CWE-693'
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

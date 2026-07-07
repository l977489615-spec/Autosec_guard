#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检测设备是否启用严格SELinux状态...

前提
假定 adb 服务已连接好 并且设备已经在 adb devices 列表中
检测项
1. 使用 getenforce 获取 SELinux 模式 Enforcing 或 Permissive
2. 读取 /sys/fs/selinux/enforce 查看是否为 1 或 0
3. 使用 getprop 查询可能相关属性作为补充
判断规则
如果任一来源表明为 Permissive 或 /sys/fs/selinux/enforce 为 0 则视为有漏洞
如果明确为 Enforcing 并且 /sys/fs/selinux/enforce 为 1 则视为安全
输出
使用 logging.warning 输出发现与摘要
注意
脚本只做只读检测 不进行写操作
"""
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
    """
    运行外部命令 并返回 (returncode, output_str)
    兼容不同平台编码 保证返回字符串
    """
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
    """
    解析 adb devices 输出 返回在线设备序列号列表
    """
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
    """
    在设备上执行 adb shell 命令
    device 为 None 表示使用默认设备
    """
    cmd = [ADB_CMD]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", shell_cmd]
    return run_cmd_try_enc(cmd, timeout=CMD_TIMEOUT)


def check_getenforce(device: str) -> Tuple[bool, str]:
    """
    使用 getenforce 检查 SELinux 模式
    返回 (ok_flag, normalized_output)
    ok_flag True 表示命令成功返回有意义值
    """
    code, out = adb_shell(device, "getenforce")
    if code < 0 or not out:
        return False, ""
    normalized = out.strip()
    return True, normalized


def check_sys_enforce(device: str) -> Tuple[bool, Optional[int]]:
    """
    读取 /sys/fs/selinux/enforce
    返回 (ok_flag, int_value_or_None)
    """
    code, out = adb_shell(device, "cat /sys/fs/selinux/enforce 2>/dev/null || true")
    if code < 0 or not out:
        return False, None
    # 找第一个数字 0 或 1
    m = re.search(r"\b([01])\b", out)
    if m:
        return True, int(m.group(1))
    return True, None


def check_getprop(device: str) -> Tuple[bool, str]:
    """
    查询部分可能相关的属性作为参考
    返回 (ok_flag, combined_props)
    """
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
    """
    对单台设备进行 SELinux 状态检测
    返回结果字典
    """
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
    """
    输出检测摘要 使用 logging.warning
    """
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

def main() -> None:
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



if __name__ == "__main__":
    main()

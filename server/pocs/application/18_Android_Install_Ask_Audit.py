#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检测设备是否允许未经警告的第三方app安装...

用途
1) 将当前目录下的 via-release-cn.apk push 到设备的 /sdcard/
2) 通过 adb 启动安装器意图:
   am start -n com.android.packageinstaller/.InstallStart -a android.intent.action.VIEW \
       -d file:///sdcard/via-release-cn.apk -t application/vnd.android.package-archive
3) 读取 dumpsys activity activities | grep "mResumedActivity" 判断最上层 Activity 是否为
   com.android.packageinstaller
   如果是 则判定为 "no vulnerability" 否则判定为 "vulnerable"
4) 最后模拟按 HOME 键返回主屏
前提
adb 已连接并可访问设备。可通过 --serial 指定目标设备序列号。
输出均使用 logging.warning
"""
POC_TAG = "13. 检测设备是否允许未经警告的第三方app安装..."

from typing import Tuple, Optional, List
import subprocess
import logging
import argparse
import os
import time
import sys
import shlex

# logging 配置
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

ADB_CMD = "adb"
APK_LOCAL_NAME = "via-release-cn.apk"
REMOTE_PATH = "/sdcard/" + APK_LOCAL_NAME
CHECK_COMPONENT = "com.android.packageinstaller"
DUMPSYS_GREP_MARK = "mResumedActivity"
PUSH_TIMEOUT = 30.0
CMD_TIMEOUT = 8.0
SLEEP_AFTER_START = 1.5  # wait for activity to appear


def run_cmd(cmd: List[str], timeout: float = CMD_TIMEOUT) -> Tuple[int, str]:
    """
    Run external command and return (returncode, text_output)
    decode stdout or stderr, ensure a string is returned
    """
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        out = proc.stdout or proc.stderr or b""
        try:
            txt = out.decode("utf-8", errors="ignore")
        except Exception:
            txt = out.decode("gbk", errors="ignore")
        return proc.returncode, txt.strip()
    except subprocess.TimeoutExpired:
        return -1, ""
    except FileNotFoundError as e:
        return -2, str(e)
    except Exception as e:
        return -3, str(e)


def adb_prefix(serial: Optional[str]) -> List[str]:
    return [ADB_CMD, "-s", serial] if serial else [ADB_CMD]


def adb_push(serial: Optional[str], local: str, remote: str) -> Tuple[bool, str]:
    cmd = adb_prefix(serial) + ["push", local, remote]
    code, out = run_cmd(cmd, timeout=PUSH_TIMEOUT)
    return code == 0, out


def adb_shell(serial: Optional[str], shell_cmd: str, timeout: float = CMD_TIMEOUT) -> Tuple[int, str]:
    cmd = adb_prefix(serial) + ["shell", shell_cmd]
    return run_cmd(cmd, timeout=timeout)


def adb_devices(serial: Optional[str] = None) -> List[str]:
    code, out = run_cmd([ADB_CMD, "devices"], timeout=3.0)
    if code != 0 or not out:
        return []
    devices = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln or ln.lower().startswith("list of devices"):
            continue
        parts = ln.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    if serial:
        return [d for d in devices if d == serial]
    return devices


def start_install_intent(serial: Optional[str]) -> Tuple[bool, str]:
    """
    Start the installer intent on the device.
    Return (success_flag, command_output_or_error)
    """
    # Build shell command string carefully, use shlex.quote where appropriate
    # Many devices accept a plain am start command without extra quoting, but we quote URI
    intent = (
        "am start -n com.android.packageinstaller/.InstallStart "
        "-a android.intent.action.VIEW "
        "-d file:///sdcard/{} -t application/vnd.android.package-archive"
    ).format(shlex.quote(APK_LOCAL_NAME))
    # Use single shell invocation
    code, out = adb_shell(serial, intent, timeout=CMD_TIMEOUT)
    return (code == 0), out


def get_top_activity_line(serial: Optional[str]) -> Optional[str]:
    """
    Run dumpsys activity activities and return the line containing mResumedActivity if found
    """
    # Use dumpsys activity activities
    cmd = "dumpsys activity activities"
    code, out = adb_shell(serial, cmd, timeout=6.0)
    if code < 0 or not out:
        return None
    # Search for a line that contains DUMPSYS_GREP_MARK
    for ln in out.splitlines():
        if DUMPSYS_GREP_MARK in ln:
            return ln.strip()
    return None


def press_home(serial: Optional[str]) -> None:
    # KEYCODE_HOME is 3
    adb_shell(serial, "input keyevent 4", timeout=2.0)


def run_check():
    parser = argparse.ArgumentParser(description="push apk, start installer intent and check top activity")
    parser.add_argument("--serial", help="adb device serial (optional)")
    parser.add_argument("--no-push", action="store_true", help="if set, do not push even if local apk exists")
    args = parser.parse_args()
    serial = args.serial

    # ensure device present if serial provided or any device
    devices = adb_devices(serial)
    if not devices:
        logging.warning("no adb devices found or specified device not online")
        sys.exit(0)

    target_device = devices[0] if not serial else serial
    logging.warning(f"target device: {target_device}")

    cwd = os.getcwd()
    local_apk_path = os.path.join(cwd, APK_LOCAL_NAME)
    if os.path.isfile(local_apk_path) and os.path.getsize(local_apk_path) > 0:
        logging.warning(f"local apk found: {local_apk_path}")
        if args.no_push:
            logging.warning("no-push flag set; skipping push")
        else:
            ok, out = adb_push(target_device, local_apk_path, REMOTE_PATH)
            if not ok:
                logging.warning(f"adb push failed: {out}")
                # still proceed to intent start even if push failed (file may already exist on device)
            else:
                logging.warning("adb push succeeded")
    else:
        # local file not present -> fail early
        logging.warning(f"local apk {APK_LOCAL_NAME} not found in current directory")
        logging.warning("aborting because apk to push is missing")
        sys.exit(0)

    # start installer intent
    ok_start, out_start = start_install_intent(target_device)
    if ok_start:
        logging.warning("started install intent (am start returned success)")
    else:
        logging.warning(f"am start returned non-zero or no output: {out_start}")

    # small delay to allow activity to come to foreground
    time.sleep(SLEEP_AFTER_START)

    # get top activity
    top_line = get_top_activity_line(target_device)
    if top_line is None:
        logging.warning("could not obtain mResumedActivity line from dumpsys; treating as inconclusive")
        # still press home to cleanup
        press_home(target_device)
        sys.exit(0)

    logging.warning(f"dumpsys mResumedActivity line: {top_line}")

    # Decide vulnerability: if top activity contains CHECK_COMPONENT then no vuln
    # else vuln
    if CHECK_COMPONENT in top_line:
        logging.warning("TOP ACTIVITY is com.android.packageinstaller -> no vulnerability")
        return False
    else:
        logging.warning("TOP ACTIVITY is NOT com.android.packageinstaller -> VULNERABLE")
        return True

    # finally press home
    press_home(target_device)
    logging.warning("pressed HOME key to return to launcher")



# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc13InstallaskPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测设备是否允许未经警告的第三方app安装...'
    meta_cve_id = 'CWE-284'
    meta_severity = 'Medium'
    meta_protocol = 'android'
    meta_target_os = ['android']
    meta_required_params = ['expected_usb_serial']
    meta_profiles = ['usb_adb']
    meta_attack_surface = '固件/USB/OTA'
    is_disruptive = True
    meta_destructive_level = 'Disruptive'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

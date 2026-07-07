#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检测设备是否启用了地址空间布局随机化（ASLR）...
0 = 禁用
1 = 基本随机化
2 = 完全随机化

前提：adb 服务已连接
"""
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


class Poc8VaspacePlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测设备是否启用了地址空间布局随机化（ASLR）...'
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

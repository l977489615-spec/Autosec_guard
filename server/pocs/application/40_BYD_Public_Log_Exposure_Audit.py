#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detect_cve_2024_54728.py

Detect CVE-2024-54728 Vulnerability (Vulnerable Log File Existence)
Vulnerability Description:
CVE-2024-54728 是一个文件权限配置漏洞，漏洞设备会在 /sdcard/logs 目录下生成日志压缩包，
格式为 "All+日期+时区.zip"（示例：All2025-10-28-02-20-47+0800.zip）。此类文件默认存储在
公共存储目录（/sdcard），即使未明确配置世界可读写权限，普通 App 也可能通过系统权限机制
访问（如存储权限、媒体库访问等），存在敏感数据泄露或日志篡改风险。

Key Features:
1. 直接通过 ADB 检测设备 /sdcard/logs 目录（无需解压 APK，快速高效）
2. 精准匹配漏洞文件格式（All+日期+时区.zip），存在即判定风险
3. 支持多设备自动检测、指定设备检测
4. 生成结构化漏洞报告（JSON 格式）
5. 兼容 Windows/Linux/macOS，Python 3.6+
"""
POC_TAG = "35. 检测设备是否存在系统日志泄露漏洞（CVE-2024-54728）..."

from typing import List, Optional, Tuple, Dict, Union
import argparse
import logging
import os
import re
import json
import subprocess
import sys
from datetime import datetime

# Logging configuration
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

ADB_CMD = "adb"
CMD_TIMEOUT = 15.0  # ADB 命令超时时间
VULN_DIR = "/sdcard/logs"  # 漏洞日志目录
# 漏洞文件格式正则：All + 日期(YYYY-MM-DD-HH-MM-SS) + 时区(±HHMM) + .zip
VULN_FILE_PATTERN = re.compile(
    r'^All'  # 固定前缀
    r'(\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})'  # 日期部分：YYYY-MM-DD-HH-MM-SS
    r'([+-]\d{4})'  # 时区部分：±HHMM（如 +0800、-0500）
    r'\.zip$',  # 后缀
    re.IGNORECASE
)
# 报告输出路径
REPORT_PATH = os.path.join(os.getcwd(), "CVE-2024-54728_Detection_Report.json")

# Type alias for vulnerability result
VulnResult = Dict[str, Union[str, bool, List[Dict[str, str]]]]


def run_adb_cmd(device_serial: Optional[str], cmd: List[str]) -> Tuple[int, str]:
    """
    执行 ADB 命令
    :param device_serial: 设备序列号（None 表示不指定设备）
    :param cmd: 命令列表
    :return: (退出码, 命令输出)
    """
    full_cmd = [ADB_CMD]
    if device_serial:
        full_cmd.extend(["-s", device_serial])
    full_cmd.extend(cmd)

    try:
        logging.debug(f"Executing ADB command: {' '.join(full_cmd)}")
        proc = subprocess.run(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=CMD_TIMEOUT,
            shell=False  # 避免 Windows 环境下的命令解析问题
        )
        # 合并 stdout 和 stderr，统一解码
        output = proc.stdout + proc.stderr
        try:
            output_str = output.decode("utf-8", errors="ignore").strip()
        except Exception:
            output_str = output.decode("gbk", errors="ignore").strip()
        return proc.returncode, output_str
    except subprocess.TimeoutExpired:
        return -1, f"ADB command timeout (>{CMD_TIMEOUT}s)"
    except FileNotFoundError:
        return -2, "ADB not found (please add ADB to system PATH or place it in current directory)"
    except Exception as e:
        return -3, f"ADB command failed: {str(e)}"


def list_adb_devices() -> List[str]:
    """获取所有在线的 ADB 设备序列号"""
    code, output = run_adb_cmd(None, ["devices"])
    if code < 0:
        logging.error(f"Failed to list devices: {output}")
        return []

    devices = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("list of devices"):
            continue
        parts = line.split(maxsplit=1)
        if len(parts) >= 2 and parts[1] == "device":  # 仅统计在线设备
            devices.append(parts[0])
    return devices


def check_vuln_dir_exists(device_serial: str) -> bool:
    """检查漏洞目录 /sdcard/logs 是否存在"""
    code, output = run_adb_cmd(device_serial, ["shell", "ls", VULN_DIR])
    # 目录存在的判断：退出码 0，且输出不含 "No such file or directory"
    if code == 0 and "No such file or directory" not in output and "没有那个文件或目录" not in output:
        logging.info(f"Device {device_serial}: Vulnerable directory {VULN_DIR} exists")
        return True
    logging.info(f"Device {device_serial}: Vulnerable directory {VULN_DIR} does not exist")
    return False


def list_files_in_vuln_dir(device_serial: str) -> List[str]:
    """列出 /sdcard/logs 目录下的所有文件"""
    code, output = run_adb_cmd(device_serial, ["shell", "ls", f"{VULN_DIR}/All*.zip"])
    if code != 0 or not output:
        logging.info(f"Device {device_serial}: No files matching 'All*.zip' in {VULN_DIR}")
        return []

    # 过滤无效行（如目录不存在提示、空行）
    files = []
    for line in output.splitlines():
        line = line.strip()
        if line and "No such file or directory" not in line and "没有那个文件或目录" not in line:
            # 提取文件名（去掉路径，仅保留文件名）
            filename = os.path.basename(line)
            files.append(filename)
    return files


def match_vuln_file_format(files: List[str]) -> List[str]:
    """筛选符合漏洞格式（All+日期+时区.zip）的文件"""
    vuln_format_files = []
    for file in files:
        if VULN_FILE_PATTERN.match(file):
            vuln_format_files.append(file)
            logging.debug(f"Matched vulnerable file format: {file}")
    return vuln_format_files


def scan_device(device_serial: str) -> VulnResult:
    """扫描单个设备是否存在 CVE-2024-54728 风险（存在漏洞格式文件即判定风险）"""
    result: VulnResult = {
        "device_serial": device_serial,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "has_vuln_risk": False,  # 是否存在漏洞风险
        "vuln_dir_exists": False,
        "matched_vuln_files": []  # 符合漏洞格式的文件列表
    }

    try:
        logging.info(f"\n===== Scanning device: {device_serial} =====")

        # Step 1: 检查漏洞目录是否存在
        result["vuln_dir_exists"] = check_vuln_dir_exists(device_serial)
        if not result["vuln_dir_exists"]:
            return result

        # Step 2: 列出目录下的 All*.zip 文件
        all_zip_files = list_files_in_vuln_dir(device_serial)
        if not all_zip_files:
            return result

        # Step 3: 筛选符合漏洞格式的文件（核心判断：存在即风险）
        result["matched_vuln_files"] = match_vuln_file_format(all_zip_files)
        if result["matched_vuln_files"]:
            result["has_vuln_risk"] = True
            logging.warning(
                f"Device {device_serial}: Found {len(result['matched_vuln_files'])} vulnerable format file(s)")
        else:
            logging.info(f"Device {device_serial}: No files match vulnerability format (All+日期+时区.zip)")

        return result

    except Exception as e:
        logging.error(f"Device {device_serial}: Scan failed - {str(e)}")
        result["error"] = str(e)
        return result


def generate_report(results: List[VulnResult]) -> bool:
    """生成 JSON 格式漏洞报告"""
    report = {
        "report_title": "CVE-2024-54728 Vulnerability Detection Report (File Existence Check)",
        "vulnerability_description": "CVE-2024-54728: Vulnerable Log File Existence in /sdcard/logs. Vulnerable devices generate logs in 'All+日期+时区.zip' format in public storage (/sdcard). Even without explicit world-writable permissions, ordinary apps may access these files via system permission mechanisms (e.g., storage permission, MediaStore access), leading to sensitive data leakage or log tampering.",
        "scan_config": {
            "vuln_dir": VULN_DIR,
            "vuln_file_pattern": VULN_FILE_PATTERN.pattern,
            "detection_rule": "If the vulnerable format file exists, it is judged to have CVE-2024-54728 risk (no permission check)",
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_devices_scanned": len(results)
        },
        "scan_results": results
    }

    try:
        with open(REPORT_PATH, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        logging.info(f"\nVulnerability report saved to: {REPORT_PATH}")
        return True
    except Exception as e:
        logging.error(f"Failed to generate report: {str(e)}")
        return False


def print_summary(results: List[VulnResult]):
    """打印扫描汇总结果"""
    logging.info(f"\n===== Scan Summary =====")
    total = len(results)
    has_risk = sum(1 for res in results if res["has_vuln_risk"])
    no_risk = total - has_risk

    logging.info(f"Total devices scanned: {total}")
    logging.info(f"Devices with CVE-2024-54728 risk: {has_risk}")
    logging.info(f"Devices without risk: {no_risk}")

    if has_risk > 0:
        logging.error("\n[HIGH RISK] CVE-2024-54728 Vulnerability Risk Detected!")
        for res in results:
            if res["has_vuln_risk"]:
                logging.error(f"\nAffected Device: {res['device_serial']}")
                logging.error(f"Vulnerable Format Files ({len(res['matched_vuln_files'])}):")
                for file in res["matched_vuln_files"]:
                    logging.error(f"  - File Path: {VULN_DIR}/{file}")

        # 漏洞风险与修复建议
        logging.error(f"\nRisk Explanation:")
        logging.error(
            f"1. Public Storage Exposure: /sdcard is a public storage directory accessible to all apps with storage permission (no root required)")
        logging.error(
            f"2. Sensitive Data Leakage: Log files may contain system configurations, user operation records, authentication information, or sensitive business data")
        logging.error(
            f"3. Log Tampering Risk: Malicious apps may modify/delete logs to bypass audit or hide malicious activities")
        logging.error(
            f"4. Permission Bypass Potential: Even with restricted file permissions, Android's MediaStore or other system mechanisms may allow app access")
        logging.error(
            f"5. Core Risk: The existence of such files in public storage violates secure logging best practices, regardless of explicit permissions")

        logging.error(f"\nFix Recommendation:")
        logging.error(f"1. Immediate Mitigation (Manual):")
        logging.error(f"   - Delete vulnerable logs: adb shell rm -rf {VULN_DIR}/All*.zip")
        logging.error(f"   - Restrict directory access: adb shell chmod 700 {VULN_DIR} (only owner can access)")
        logging.error(f"2. Permanent Fix (Application/System Update):")
        logging.error(
            f"   - Migrate logs to app-private directory: Use /data/data/<your-package-name>/files/logs (only the app itself can access)")
        logging.error(
            f"   - Avoid public storage for sensitive logs: Never store audit logs, authentication data, or system configurations in /sdcard")
        logging.error(
            f"   - Set strict file permissions: For unavoidable public storage usage, set permissions to 600 (-rw-------) or 640 (-rw-r-----)")
        logging.error(
            f"   - Implement log encryption: Encrypt sensitive logs before storage (even if accessed, data remains unreadable)")
        logging.error(f"3. Post-Fix Verification:")
        logging.error(f"   - Re-run this script to confirm no vulnerable format files exist in {VULN_DIR}")
        logging.error(
            f"   - Verify logs are stored in app-private directory (check /data/data/<your-package-name>/files/logs)")
        logging.error(
            f"   - Audit log generation logic: Ensure no new vulnerable format files are generated in public storage")
    else:
        logging.info("\n[SAFE] No CVE-2024-54728 Vulnerability Risk Detected")
        logging.info(f"All scanned devices do not have vulnerable format files in {VULN_DIR}")


def run_check():
    parser = argparse.ArgumentParser(description="Detect CVE-2024-54728 Vulnerability Risk (File Existence Check)")
    parser.add_argument("--serial", help="Specify ADB device serial (optional; auto-detect all online devices)")
    args = parser.parse_args()

    # Step 1: 获取目标设备列表
    if args.serial:
        devices = [args.serial]
        # 验证设备是否在线
        code, output = run_adb_cmd(args.serial, ["shell", "echo", "ok"])
        if code != 0:
            logging.error(f"Device {args.serial} is not online or inaccessible")
            sys.exit(1)
    else:
        devices = list_adb_devices()
        if not devices:
            logging.error("No online ADB devices detected. Please connect a device and enable USB debugging.")
            sys.exit(1)
        logging.info(f"Detected {len(devices)} online device(s): {devices}")

    # Step 2: 扫描所有目标设备
    scan_results = []
    for device in devices:
        result = scan_device(device)
        scan_results.append(result)

    # Step 3: 生成报告和汇总
    generate_report(scan_results)
    print_summary(scan_results)

    # 退出码：存在风险则返回 1，否则返回 0（便于自动化集成）
    return any(res["has_vuln_risk"] for res in scan_results)



# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc35BydlogPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测设备是否存在系统日志泄露漏洞（CVE-2024-54728）...'
    meta_cve_id = 'CVE-2024-54728'
    meta_severity = 'Low'
    meta_protocol = 'local'
    meta_target_os = ['android', 'linux']
    meta_required_params = ['expected_usb_serial']
    meta_profiles = ['application']
    meta_attack_surface = '车机APP/应用'
    is_disruptive = False
    meta_destructive_level = 'Safe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

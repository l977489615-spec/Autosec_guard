#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detect_byd_data_collect_vuln.py

Detect Vulnerability with Specific Features:
1. Exists directory: /system/priv-app/CanDataCollect/
2. getprop ro.build.fingerprint contains "20230526"
3. dumpsys package | grep -i com.byd.data_collection_notify returns empty

Vulnerability Description:
The vulnerability exists when three conditions are simultaneously met:
- The privileged app directory /system/priv-app/CanDataCollect/ exists (indicates potential sensitive data collection app)
- System build fingerprint contains "20230526" (specific vulnerable version marker)
- The package com.byd.data_collection_notify is not found in system packages (may indicate incomplete app installation or permission misconfiguration)
This combination may lead to sensitive data leakage, unauthorized data collection, or system permission bypass.
"""
POC_TAG = "36. 检测设备是否存在CAN流量劫持漏洞（CVE-2025-28169）..."

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
CMD_TIMEOUT = 20.0  # ADB command timeout
# Vulnerability related configuration
VULN_DIR = "/system/priv-app/CanDataCollect/"
FINGERPRINT_MARKER = "20230526"
TARGET_PACKAGE = "com.byd.data_collection_notify"
# Report output path
REPORT_PATH = os.path.join(os.getcwd(), "BYD_DataCollect_Vulnerability_Report.json")

# Type alias for vulnerability result
VulnResult = Dict[str, Union[str, bool, Dict[str, bool]]]


def run_adb_cmd(device_serial: Optional[str], cmd: List[str]) -> Tuple[int, str]:
    """
    Execute ADB command
    :param device_serial: Device serial number (None for no specific device)
    :param cmd: Command list
    :return: (exit_code, output_str)
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
            shell=False  # Avoid command parsing issues on Windows
        )
        # Merge stdout and stderr, decode uniformly
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
    """Get all online ADB device serial numbers"""
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
        if len(parts) >= 2 and parts[1] == "device":  # Only count online devices
            devices.append(parts[0])
    return devices


def check_vuln_dir_exists(device_serial: str) -> Tuple[bool, str]:
    """
    Check if /system/priv-app/CanDataCollect/ directory exists
    :return: (exists_flag, detail_msg)
    """
    # Use ls command to check directory existence (Android requires root for /system access in some cases)
    code, output = run_adb_cmd(device_serial, ["shell", "ls", VULN_DIR])
    # Directory exists if exit code 0 and no "No such file or directory" in output
    exists = False
    if code == 0:
        if "No such file or directory" not in output and "没有那个文件或目录" not in output:
            exists = True
            detail = f"Directory {VULN_DIR} exists"
        else:
            detail = f"Directory {VULN_DIR} does not exist (ls command returned 'No such file or directory')"
    else:
        detail = f"Failed to check directory: exit code {code}, output: {output}"
    logging.info(f"Device {device_serial}: {detail}")
    return exists, detail


def check_fingerprint_contains_marker(device_serial: str) -> Tuple[bool, str, str]:
    """
    Check if getprop ro.build.fingerprint contains FINGERPRINT_MARKER (20230526)
    :return: (contains_flag, fingerprint_value, detail_msg)
    """
    code, output = run_adb_cmd(device_serial, ["shell", "getprop", "ro.build.fingerprint"])
    if code != 0:
        detail = f"Failed to get fingerprint: exit code {code}, output: {output}"
        logging.warning(f"Device {device_serial}: {detail}")
        return False, "", detail

    fingerprint = output.strip()
    contains = FINGERPRINT_MARKER in fingerprint
    detail = f"Fingerprint: {fingerprint} (contains '{FINGERPRINT_MARKER}': {contains})"
    logging.info(f"Device {device_serial}: {detail}")
    return contains, fingerprint, detail


def check_target_package_empty(device_serial: str) -> Tuple[bool, str]:
    """
    Check if dumpsys package | grep -i {TARGET_PACKAGE} returns empty
    :return: (is_empty_flag, detail_msg)
    """
    # Combine dumpsys and grep command (use Android's built-in grep)
    cmd = [
        "shell",
        f"dumpsys package | grep -i {TARGET_PACKAGE} || echo 'grep_empty_marker'"
    ]
    code, output = run_adb_cmd(device_serial, cmd)

    # Judge if output is empty (grep returns 1 when no match, so we add a marker for judgment)
    is_empty = False
    if "grep_empty_marker" in output:
        is_empty = True
        detail = f"Package query returns empty (no {TARGET_PACKAGE} found)"
    elif code == 0 and not output.strip():
        is_empty = True
        detail = f"Package query returns empty (no {TARGET_PACKAGE} found)"
    elif code == 1 and not output.strip():
        is_empty = True
        detail = f"Package query returns empty (no {TARGET_PACKAGE} found)"
    else:
        detail = f"Package query returns non-empty: {output[:200]}..."  # Truncate long output

    logging.info(f"Device {device_serial}: {detail}")
    return is_empty, detail


def scan_device(device_serial: str) -> VulnResult:
    """Scan single device for vulnerability (all three conditions must be met)"""
    result: VulnResult = {
        "device_serial": device_serial,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "is_vulnerable": False,
        "condition_checks": {
            "dir_exists": False,
            "fingerprint_contains_marker": False,
            "package_query_empty": False
        },
        "details": {}
    }

    try:
        logging.info(f"\n===== Scanning device: {device_serial} =====")

        # Step 1: Check vulnerability directory existence
        dir_exists, dir_detail = check_vuln_dir_exists(device_serial)
        result["condition_checks"]["dir_exists"] = dir_exists
        result["details"]["dir_check"] = dir_detail

        # Step 2: Check fingerprint contains marker
        fp_contains, fp_value, fp_detail = check_fingerprint_contains_marker(device_serial)
        result["condition_checks"]["fingerprint_contains_marker"] = fp_contains
        result["details"]["fingerprint_check"] = fp_detail
        result["details"]["fingerprint_value"] = fp_value

        # Step 3: Check target package query is empty
        pkg_empty, pkg_detail = check_target_package_empty(device_serial)
        result["condition_checks"]["package_query_empty"] = pkg_empty
        result["details"]["package_check"] = pkg_detail

        # Step 4: Judge vulnerability (all three conditions must be True)
        all_conditions_met = (
                dir_exists and
                fp_contains and
                pkg_empty
        )
        result["is_vulnerable"] = all_conditions_met

        if all_conditions_met:
            logging.error(f"Device {device_serial}: ALL THREE VULNERABILITY CONDITIONS ARE MET!")
        else:
            unmet_conditions = []
            if not dir_exists:
                unmet_conditions.append("Directory {VULN_DIR} does not exist")
            if not fp_contains:
                unmet_conditions.append(f"Fingerprint does not contain '{FINGERPRINT_MARKER}'")
            if not pkg_empty:
                unmet_conditions.append(f"Package {TARGET_PACKAGE} query is not empty")
            logging.info(
                f"Device {device_serial}: Vulnerability not found (unmet conditions: {', '.join(unmet_conditions)})")

        return result

    except Exception as e:
        error_msg = f"Scan failed: {str(e)}"
        logging.error(f"Device {device_serial}: {error_msg}")
        result["error"] = error_msg
        return result


def generate_report(results: List[VulnResult]) -> bool:
    """Generate JSON format vulnerability report"""
    report = {
        "report_title": "BYD DataCollect Vulnerability Detection Report",
        "vulnerability_description": (
            "Vulnerability is confirmed when all three following conditions are met:\n"
            f"1. Directory {VULN_DIR} exists (privileged app directory for potential data collection)\n"
            f"2. System build fingerprint (ro.build.fingerprint) contains '{FINGERPRINT_MARKER}' (specific vulnerable version)\n"
            f"3. Query package {TARGET_PACKAGE} via dumpsys returns empty (incomplete app or permission misconfiguration)\n"
            "Risk: Sensitive data leakage, unauthorized data collection, system permission bypass"
        ),
        "scan_config": {
            "vulnerable_dir": VULN_DIR,
            "fingerprint_marker": FINGERPRINT_MARKER,
            "target_package": TARGET_PACKAGE,
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
    """Print scan summary"""
    logging.info(f"\n===== Scan Summary =====")
    total = len(results)
    vulnerable = sum(1 for res in results if res["is_vulnerable"])
    safe = total - vulnerable
    failed = sum(1 for res in results if "error" in res)

    logging.info(f"Total devices scanned: {total}")
    logging.info(f"Vulnerable devices: {vulnerable}")
    logging.info(f"Safe devices: {safe}")
    logging.info(f"Scan failed devices: {failed}")

    if vulnerable > 0:
        logging.error("\n[CRITICAL VULNERABILITY] Vulnerable Devices Detected!")
        for res in results:
            if res["is_vulnerable"]:
                logging.error(f"\nVulnerable Device: {res['device_serial']}")
                logging.error(f"Conditions Met:")
                logging.error(f"  1. Directory exists: {res['condition_checks']['dir_exists']}")
                logging.error(
                    f"  2. Fingerprint contains '{FINGERPRINT_MARKER}': {res['condition_checks']['fingerprint_contains_marker']}")
                logging.error(f"  3. Package query empty: {res['condition_checks']['package_query_empty']}")

        logging.error(f"\nRisk Explanation:")
        logging.error(
            f"1. Privileged App Directory Exposure: {VULN_DIR} is a privileged app directory, which may contain apps with high system permissions")
        logging.error(
            f"2. Vulnerable Version Marker: Fingerprint containing '{FINGERPRINT_MARKER}' indicates the device uses a specific version with potential security flaws")
        logging.error(
            f"3. Missing Package Notification: The absence of {TARGET_PACKAGE} may mean the data collection notification mechanism is incomplete, leading to unauthorized data collection without user awareness")
        logging.error(
            f"4. Combined Risk: High-privilege data collection app exists in a vulnerable system version, and the lack of notification mechanism increases the risk of sensitive data leakage")

        logging.error(f"\nFix Recommendation:")
        logging.error(f"1. Immediate Mitigation:")
        logging.error(f"   - Check the legitimacy of {VULN_DIR}: adb shell ls -l {VULN_DIR}")
        logging.error(
            f"   - Remove unauthorized directory (if confirmed malicious): adb root && adb shell rm -rf {VULN_DIR}")
        logging.error(f"   - Verify system integrity: adb shell md5sum /system/build.prop (compare with official hash)")
        logging.error(f"2. System Update:")
        logging.error(
            f"   - Update to the latest official system version (avoid versions with fingerprint containing '{FINGERPRINT_MARKER}')")
        logging.error(f"   - Install missing security patches: Contact device manufacturer (BYD) for official updates")
        logging.error(f"3. App and Permission Management:")
        logging.error(
            f"   - Install the official {TARGET_PACKAGE} package (if required by the system): adb install -r official_package.apk")
        logging.error(
            f"   - Restrict app permissions: Use adb shell pm revoke to remove unnecessary permissions for apps in {VULN_DIR}")
        logging.error(f"4. Post-Fix Verification:")
        logging.error(f"   - Re-run this script to confirm all three vulnerability conditions are no longer met")
        logging.error(
            f"   - Verify fingerprint does not contain '{FINGERPRINT_MARKER}': adb shell getprop ro.build.fingerprint")
        logging.error(f"   - Confirm {TARGET_PACKAGE} is installed: adb shell dumpsys package {TARGET_PACKAGE}")
    else:
        logging.info(f"\n[SAFE] No Vulnerable Devices Detected")
        logging.info(f"All scanned devices do not meet all three vulnerability conditions")


def run_check():
    parser = argparse.ArgumentParser(
        description="Detect Vulnerability with Three Conditions (Directory + Fingerprint + Package)")
    parser.add_argument("--serial", help="Specify ADB device serial (optional; auto-detect all online devices)")
    args = parser.parse_args()

    # Step 1: Get target devices
    if args.serial:
        devices = [args.serial]
        # Verify device is online
        code, output = run_adb_cmd(args.serial, ["shell", "echo", "ok"])
        if code != 0:
            logging.error(f"Device {args.serial} is not online or inaccessible: {output}")
            return False
    else:
        devices = list_adb_devices()
        if not devices:
            logging.error("No online ADB devices detected. Please connect a device and enable USB debugging.")
            return False
        logging.info(f"Detected {len(devices)} online device(s): {devices}")

    # Step 2: Scan all target devices
    scan_results = []
    for device in devices:
        result = scan_device(device)
        scan_results.append(result)

    # Step 3: Generate report and summary
    generate_report(scan_results)
    print_summary(scan_results)

    # Exit code: 1 if vulnerable devices exist, 0 otherwise (for automation integration)
    return any(res["is_vulnerable"] for res in scan_results)



# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc36BydtrafficHijackPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测设备是否存在CAN流量劫持漏洞（CVE-2025-28169）...'
    meta_cve_id = 'CVE-2025-28169'
    meta_severity = 'High'
    meta_protocol = 'can'
    meta_target_os = ['android']
    meta_required_params = ['can_interface']
    meta_profiles = ['can_extended']
    meta_attack_surface = 'CAN/UDS/OBD'
    is_disruptive = False
    meta_destructive_level = 'Medium'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

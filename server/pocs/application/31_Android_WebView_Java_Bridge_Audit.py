#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detect_addJavascriptInterface_vuln.py

Detect WebView addJavascriptInterface Vulnerability in CarSetting.apk
Vulnerability Description:
WebView's addJavascriptInterface method exposes Java objects to JavaScript.
If the WebView loads untrusted HTML/JS (e.g., from the internet), attackers can use this interface to execute arbitrary code,
steal sensitive data, or control the device.

Key Features:
1. Build JSON-format API-Class map (saved as APIMap_CarSetting_addJavascriptInterface.json)
2. Detect addJavascriptInterface calls (core vulnerability API)
3. Reuse existing decoded folders with prefix "decoded_CarSetting.apk_"
4. Compatible with Python 3.6+
5. Auto-save API map to current directory
"""
POC_TAG = "26. 检测设备app是否使用了不安全的Webview本地Java接口..."

from typing import List, Optional, Tuple, Dict, Set, Union
import argparse
import logging
import os
import re
import json
import shutil
import subprocess
import sys
import fnmatch

# Logging configuration
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

ADB_CMD = "adb"
CMD_TIMEOUT = 10.0
# Target APK information
TARGET_APK_NAME = "CarSetting.apk"
REMOTE_APK_PATHS = [
    "/system/priv-app/CarSetting/CarSetting.apk",
    "/system/app/CarSetting/CarSetting.apk",
    "/vendor/priv-app/CarSetting/CarSetting.apk"
]
# Decoded folder prefix
DECODED_FOLDER_PREFIX = "decoded_CarSetting.apk_"
# Fixed JSON output path (current directory + fixed filename)
JSON_OUTPUT_PATH = os.path.join(os.getcwd(), "APIMap_CarSetting_addJavascriptInterface.json")

# ==========================
# Configuration: Target API (addJavascriptInterface)
# 核心API：WebView.addJavascriptInterface(Object obj, String name)
# 方法签名：Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
# ==========================
TARGET_APIS = {
    "WebView.addJavascriptInterface(Object, String)": {
        "smali_patterns": [
            # 精确匹配完整invoke指令（支持参数空格、换行）
            re.compile(
                r'invoke-virtual\s*\{\s*.+?\s*\}\s*Landroid/webkit/WebView;->addJavascriptInterface\(Ljava/lang/Object;Ljava/lang/String;\)V',
                re.IGNORECASE | re.DOTALL
            ),
            # 匹配方法签名核心部分（避免参数格式差异）
            re.compile(
                r'Landroid/webkit/WebView;->addJavascriptInterface\(Ljava/lang/Object;Ljava/lang/String;\)V',
                re.IGNORECASE
            ),
            # 模糊匹配方法名（应对简化的指令格式）
            re.compile(
                r'addJavascriptInterface\(Ljava/lang/Object;Ljava/lang/String;\)V',
                re.IGNORECASE
            )
        ],
        "full_method": "Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V"
    }
}

# Type alias for API-Class map
ApiClassMap = Dict[str, List[Dict[str, Union[str, List[int]]]]]


def run_cmd(cmd: List[str], timeout: float = CMD_TIMEOUT) -> Tuple[int, str]:
    """Execute system command and return exit code and output"""
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
        )
        out = proc.stdout or proc.stderr or b""
        try:
            txt = out.decode("utf-8", errors="ignore")
        except Exception:
            txt = out.decode("gbk", errors="ignore")
        return proc.returncode, txt.strip()
    except subprocess.TimeoutExpired:
        return -1, "command timeout"
    except FileNotFoundError as e:
        return -2, str(e)
    except Exception as e:
        return -3, str(e)


def list_adb_devices() -> List[str]:
    """Get list of connected ADB devices"""
    code, out = run_cmd([ADB_CMD, "devices"], timeout=4.0)
    if code < 0 or not out:
        return []
    devices = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln or ln.lower().startswith("list of devices"):
            continue
        parts = ln.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


def remote_path_exists(device: str, path: str) -> bool:
    """Check if path exists on ADB device"""
    code, out = run_cmd([ADB_CMD, "-s", device, "shell", "ls", path], timeout=6.0)
    if code < 0:
        return False
    if "No such file" in out or "没有那个文件或目录" in out:
        return False
    return True


def adb_pull(device: str, remote: str, local: str) -> bool:
    """Pull file from ADB device to local"""
    code, out = run_cmd([ADB_CMD, "-s", device, "pull", remote, local], timeout=60.0)
    if code == 0 and os.path.exists(local) and os.path.getsize(local) > 0:
        return True
    if os.path.exists(local):
        os.remove(local)
    return False


def local_apk_exists() -> Optional[str]:
    """Check if target APK exists in current directory"""
    local_apk_path = os.path.join(os.getcwd(), TARGET_APK_NAME)
    if os.path.isfile(local_apk_path) and os.path.getsize(local_apk_path) > 0:
        logging.info(f"Found local APK: {local_apk_path}")
        return local_apk_path
    logging.info(f"No local {TARGET_APK_NAME} found")
    return None


def find_existing_decoded_folder() -> Optional[str]:
    """Find existing valid decoded folder with prefix 'decoded_CarSetting.apk_'"""
    cwd = os.getcwd()
    for item in os.listdir(cwd):
        item_path = os.path.join(cwd, item)
        if os.path.isdir(item_path) and item.startswith(DECODED_FOLDER_PREFIX):
            # 支持 smali、smali_classes2/3/4 目录（适配多dex APK）
            smali_dirs = [
                os.path.join(item_path, "smali"),
                os.path.join(item_path, "smali_classes2"),
                os.path.join(item_path, "smali_classes3"),
                os.path.join(item_path, "smali_classes4")
            ]
            valid_smali_dir = None
            for smali_dir in smali_dirs:
                if os.path.exists(smali_dir) and os.listdir(smali_dir):
                    valid_smali_dir = smali_dir
                    break

            if valid_smali_dir:
                logging.info(f"Found valid existing decoded folder: {item_path} (smali dir: {valid_smali_dir})")
                return item_path
            else:
                logging.warning(f"Folder {item_path} is invalid (no valid smali directory)")
    logging.info("No existing valid decoded folder found")
    return None


def apktool_cmd() -> Optional[str]:
    """Get valid apktool command (prioritize ./apktool, fallback to system)"""
    cwd_tool_bat = os.path.join(os.getcwd(), "apktool.bat")
    if os.path.isfile(cwd_tool_bat) and os.access(cwd_tool_bat, os.X_OK):
        logging.info(f"Found apktool (Windows): {cwd_tool_bat}")
        return "apktool.bat"
    cwd_tool = os.path.join(os.getcwd(), "apktool")
    if os.path.isfile(cwd_tool) and os.access(cwd_tool, os.X_OK):
        logging.info(f"Found apktool (Linux/macOS): {cwd_tool}")
        return cwd_tool
    code, _ = run_cmd(["apktool", "--version"], timeout=3.0)
    if code >= 0:
        logging.info(f"Found system apktool")
        return "apktool"
    logging.error("apktool not found (check current directory or system PATH)")
    return None


def try_apktool_decode(apk_path: str, out_dir: str, apktool_path: str) -> bool:
    """Decode APK with apktool (enable smali decompilation)"""
    cmd = [apktool_path, "d", "-f", apk_path, "-o", out_dir]
    logging.info(f"Running apktool command: {' '.join(cmd)}")
    code, out = run_cmd(cmd, timeout=300.0)
    if code != 0:
        logging.error(f"apktool decode failed: {out}")
        return False

    # 验证smali目录（支持多dex）
    smali_dirs = [
        os.path.join(out_dir, "smali"),
        os.path.join(out_dir, "smali_classes2"),
        os.path.join(out_dir, "smali_classes3")
    ]
    valid_smali_dirs = [d for d in smali_dirs if os.path.exists(d) and os.listdir(d)]
    if not valid_smali_dirs:
        logging.error("Decompilation succeeded but no valid smali directories found")
        return False

    logging.info(f"APK decompiled successfully: {out_dir} (valid smali dirs: {valid_smali_dirs})")
    return True


def build_api_class_map(smali_root_list: List[str]) -> ApiClassMap:
    """Build API-Class map by scanning all valid smali directories"""
    api_class_map: ApiClassMap = {api_name: [] for api_name in TARGET_APIS.keys()}

    logging.info(f"\nBuilding API-Class map (scanning {len(smali_root_list)} smali directories)...")
    total_files_scanned = 0

    for smali_root in smali_root_list:
        for root, dirs, files in os.walk(smali_root):
            for file in fnmatch.filter(files, "*.smali"):
                total_files_scanned += 1
                smali_path = os.path.join(root, file)
                try:
                    with open(smali_path, "r", encoding="utf-8", errors="ignore") as f:
                        smali_lines = f.read().splitlines()
                except Exception as e:
                    logging.warning(f"Failed to read smali file: {smali_path} (error: {e})")
                    continue

                # Check each target API against current smali file
                for api_name, api_config in TARGET_APIS.items():
                    line_numbers: List[int] = []
                    for pattern in api_config["smali_patterns"]:
                        for line_idx, line in enumerate(smali_lines, 1):
                            if pattern.search(line) and line_idx not in line_numbers:
                                line_numbers.append(line_idx)

                    if line_numbers:
                        # 检查是否已存在该文件的调用记录
                        file_entry_exists = False
                        for entry in api_class_map[api_name]:
                            if entry["smali_file"] == smali_path:
                                entry["line_numbers"].extend(
                                    [ln for ln in line_numbers if ln not in entry["line_numbers"]])
                                file_entry_exists = True
                                break
                        if not file_entry_exists:
                            api_class_map[api_name].append({
                                "smali_file": smali_path,
                                "line_numbers": line_numbers
                            })

    logging.info(f"\nAPI-Class map built successfully:")
    logging.info(f"- Total smali files scanned: {total_files_scanned}")
    for api_name, callers in api_class_map.items():
        logging.info(f"- {api_name}: called by {len(callers)} smali file(s)")
    return api_class_map


def save_api_class_map(api_class_map: ApiClassMap) -> bool:
    """Auto-save API-Class map to JSON file"""
    try:
        json_content = {
            "description": "API-Class map for addJavascriptInterface vulnerability detection",
            "target_api": TARGET_APIS,
            "api_class_map": api_class_map
        }
        with open(JSON_OUTPUT_PATH, "w", encoding="utf-8") as f:
            json.dump(json_content, f, ensure_ascii=False, indent=2)
        logging.info(f"\nAPI-Class map saved to: {JSON_OUTPUT_PATH}")
        return True
    except Exception as e:
        logging.info(f"Failed to save API-Class map to {JSON_OUTPUT_PATH}: {e}")
        return False


def get_or_create_decoded_folder(apk_path: str, device: str) -> Optional[str]:
    """Reuse existing decoded folder or create new one"""
    # Check existing folder first
    existing_decoded = find_existing_decoded_folder()
    if existing_decoded:
        return existing_decoded

    # Create new folder
    device_safe = device.replace(":", "_")
    new_decoded_dir = os.path.join(os.getcwd(), f"{DECODED_FOLDER_PREFIX}{device_safe}")
    logging.info(f"Preparing to decode APK to: {new_decoded_dir}")

    at_cmd = apktool_cmd()
    if not at_cmd:
        return None

    # Delete old folder if exists
    if os.path.exists(new_decoded_dir):
        logging.info(f"Deleting old decoded folder: {new_decoded_dir}")
        try:
            shutil.rmtree(new_decoded_dir)
        except Exception as e:
            logging.warning(f"Failed to delete old decoded folder: {e}")
            return None

    # Decode APK
    if try_apktool_decode(apk_path, new_decoded_dir, at_cmd):
        return new_decoded_dir
    else:
        logging.error("Failed to create new decoded folder")
        return None


def analyze_vulnerability(api_class_map: ApiClassMap) -> Tuple[bool, Dict[str, List[Dict[str, Union[str, List[int]]]]]]:
    """Detect vulnerability by checking addJavascriptInterface calls"""
    vulnerable_api_details: Dict[str, List[Dict[str, Union[str, List[int]]]]] = {}
    is_vulnerable = False

    for api_name, callers in api_class_map.items():
        if callers:
            vulnerable_api_details[api_name] = callers
            is_vulnerable = True

    return is_vulnerable, vulnerable_api_details


def process_device(device: str) -> bool:
    """Process single device: get APK → build API map → detect vulnerability"""
    logging.info(f"\n===== Processing device: {device} =====")

    # Step 1: Get target APK
    apk_path = local_apk_exists()
    if not apk_path:
        logging.info(f"Pulling {TARGET_APK_NAME} from device {device}...")
        for remote_path in REMOTE_APK_PATHS:
            if remote_path_exists(device, remote_path):
                local_apk_path = os.path.join(os.getcwd(), TARGET_APK_NAME)
                if adb_pull(device, remote_path, local_apk_path):
                    apk_path = local_apk_path
                    logging.info(f"Successfully pulled APK to: {apk_path}")
                    break
                else:
                    logging.warning(f"Failed to pull APK from {remote_path}")
        if not apk_path:
            logging.error(f"Failed to get {TARGET_APK_NAME}. Skipping device.")
            return False

    # Step 2: Get decoded folder
    decoded_dir = get_or_create_decoded_folder(apk_path, device)
    if not decoded_dir:
        logging.error("No valid decoded folder. Skipping analysis.")
        return False

    # Step 3: Collect all valid smali directories (support multi-dex)
    smali_root_list = []
    smali_dir_candidates = [
        os.path.join(decoded_dir, "smali"),
        os.path.join(decoded_dir, "smali_classes2"),
        os.path.join(decoded_dir, "smali_classes3"),
        os.path.join(decoded_dir, "smali_classes4")
    ]
    for dir_candidate in smali_dir_candidates:
        if os.path.exists(dir_candidate) and len(os.listdir(dir_candidate)) > 0:
            smali_root_list.append(dir_candidate)
    if not smali_root_list:
        logging.error(f"No valid smali directories found in {decoded_dir}")
        return False

    # Step 4: Build API-Class map + auto-save to JSON
    api_class_map = build_api_class_map(smali_root_list)
    save_api_class_map(api_class_map)

    # Step 5: Detect vulnerability
    logging.info(f"\n===== Vulnerability Detection Result =====")
    is_vulnerable, vulnerable_api_details = analyze_vulnerability(api_class_map)

    if is_vulnerable:
        logging.error("[VULNERABLE] addJavascriptInterface API calls detected!")
        for api_name, callers in vulnerable_api_details.items():
            logging.error(f"\nVulnerable API: {api_name}")
            logging.error(f"Called in {len(callers)} file(s):")
            for caller in callers:
                logging.error(f"  - File: {caller['smali_file']}")
                logging.error(f"    Line Numbers: {', '.join(map(str, caller['line_numbers']))}")

        logging.error(f"\nRisk Explanation:")
        logging.error(f"1. addJavascriptInterface exposes Java objects to JavaScript")
        logging.error(f"2. If WebView loads untrusted content (internet/SD card), attackers can execute arbitrary code")
        logging.error(f"3. Impact: Steal sensitive data, control device, install malware")

        logging.error(f"\nFix Recommendation:")
        logging.error(f"1. Avoid using addJavascriptInterface if possible")
        logging.error(f"2. If necessary:")
        logging.error(f"   - Only load trusted HTML/JS (local assets, not internet/SD card)")
        logging.error(f"   - Use @JavascriptInterface annotation (Android 4.2+) to restrict exposed methods")
        logging.error(
            f"   - Disable WebView JavaScript if not needed (webView.getSettings().setJavaScriptEnabled(false))")
        logging.error(f"3. For Android < 4.2: Use alternative communication methods (e.g., shouldOverrideUrlLoading)")
        return True
    else:
        logging.info("[SAFE] No addJavascriptInterface API calls detected")
        logging.info(f"Target API: {list(TARGET_APIS.keys())[0]}")
        return False


def run_check():
    parser = argparse.ArgumentParser(
        description="Detect WebView addJavascriptInterface Vulnerability (auto-save API map)")
    parser.add_argument("--serial", help="Specify ADB device serial (optional; auto-detect online devices)")
    args = parser.parse_args()

    # Get target devices
    devices = [args.serial] if args.serial else list_adb_devices()
    if not devices:
        logging.error("No online ADB devices detected. Ensure ADB is connected.")
        sys.exit(1)
    logging.info(f"Detected {len(devices)} online device(s): {devices}")

    # Process all devices
    overall_vulnerable = False
    for device in devices:
        if process_device(device):
            overall_vulnerable = True

    return overall_vulnerable



# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc26WebviewJavaPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测设备app是否使用了不安全的Webview本地Java接口...'
    meta_cve_id = 'CWE-749'
    meta_severity = 'High'
    meta_protocol = 'android'
    meta_target_os = ['android', 'linux']
    meta_required_params = ['expected_usb_serial']
    meta_profiles = ['application']
    meta_attack_surface = '车机APP/应用'
    is_disruptive = False
    meta_destructive_level = 'Probe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

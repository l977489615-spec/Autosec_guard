#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detect_getSharedPreferences_world_writeable_vuln.py

Detect getSharedPreferences(..., MODE_WORLD_WRITEABLE) Vulnerability in CarSetting.apk
Vulnerability Description:
Context.getSharedPreferences(String name, int mode) 用于获取应用的偏好设置存储实例。
若第二个参数包含 MODE_WORLD_WRITEABLE（值为 0x02），表示偏好设置文件（.xml 格式）对设备上所有应用可写，
攻击者可通过其他应用篡改其中存储的敏感配置（如用户状态、认证标识、应用参数），导致账号劫持、权限绕过、应用逻辑异常甚至远程代码执行。

Key Features:
1. Build JSON-format API-Class map (saved as APIMap_CarSetting_getSharedPreferences_writeable.json)
2. Detect getSharedPreferences calls with MODE_WORLD_WRITEABLE (core vulnerable configuration)
3. Reuse existing decoded folders with prefix "decoded_CarSetting.apk_"
4. Compatible with Python 3.6+
5. Auto-save API map to current directory
"""
POC_TAG = "32. 检测设备app是否使用了不安全的数据库全局可写访问接口..."

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
JSON_OUTPUT_PATH = os.path.join(os.getcwd(), "APIMap_CarSetting_getSharedPreferences_writeable.json")

# ==========================
# Configuration: Target API (getSharedPreferences + MODE_WORLD_WRITEABLE)
# 核心API：Context.getSharedPreferences(String name, int mode)
# 方法签名：Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
# 漏洞点：mode 参数包含 MODE_WORLD_WRITEABLE（值 0x02，二进制 0010）
# 注意：mode 支持组合（如 MODE_WORLD_READABLE | MODE_WORLD_WRITEABLE = 0x03），只要包含 0x02 即漏洞
# ==========================
TARGET_APIS = {
    "Context.getSharedPreferences(..., MODE_WORLD_WRITEABLE)": {
        "smali_patterns": [
            # 1. 精确匹配 mode = MODE_WORLD_WRITEABLE（单独使用，值 0x2）
            re.compile(
                r'invoke-virtual\s*\{\s*.+?,\s*.+?,\s*0x2\s*\}\s*Landroid/content/Context;->getSharedPreferences\(Ljava/lang/String;I\)Landroid/content/SharedPreferences;',
                re.IGNORECASE | re.DOTALL
            ),
            # 2. 匹配 mode 组合（如 0x2 | 0x1 = 0x3、0x2 | 0x4 = 0x6，只要包含 0x2 即匹配）
            re.compile(
                r'Landroid/content/Context;->getSharedPreferences\(Ljava/lang/String;I\)Landroid/content/SharedPreferences;\s*.+?(0x[2367acef])',
                re.IGNORECASE | re.DOTALL
            ),
            # 3. 模糊匹配：方法签名 + 0x2 参数（兼容参数位置差异）
            re.compile(
                r'getSharedPreferences\(Ljava/lang/String;I\)Landroid/content/SharedPreferences;.*?0x2|0x2.*?getSharedPreferences\(Ljava/lang/String;I\)Landroid/content/SharedPreferences;',
                re.IGNORECASE | re.DOTALL
            ),
            # 4. 匹配常量引用（部分代码用常量名而非直接写 0x2，如 MODE_WORLD_WRITEABLE）
            re.compile(
                r'Landroid/content/Context;->MODE_WORLD_WRITEABLE\s*.+?getSharedPreferences',
                re.IGNORECASE | re.DOTALL
            )
        ],
        "full_method": "Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;",
        "vulnerable_param": "mode contains MODE_WORLD_WRITEABLE (0x2, world-writable permission)",
        "mode_explanation": {
            "MODE_WORLD_WRITEABLE": "0x2 (0010) - All apps can write to the SharedPreferences file",
            "MODE_PRIVATE": "0x0 (0000) - Only current app can access (safe, default)",
            "MODE_WORLD_READABLE": "0x1 (0001) - All apps can read (high risk)",
            "MODE_MULTI_PROCESS": "0x4 (0100) - Deprecated, multi-process access (combined with 0x2 still vulnerable)",
            "Combination Example": "0x3 = 0x1 | 0x2 (world-readable + world-writable - critical risk)"
        }
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
            "description": "API-Class map for getSharedPreferences(..., MODE_WORLD_WRITEABLE) vulnerability detection",
            "target_api": TARGET_APIS,
            "api_class_map": api_class_map
        }
        with open(JSON_OUTPUT_PATH, "w", encoding="utf-8") as f:
            json.dump(json_content, f, ensure_ascii=False, indent=2)
        logging.info(f"\nAPI-Class map saved to: {JSON_OUTPUT_PATH}")
        return True
    except Exception as e:
        logging.error(f"Failed to save API-Class map to {JSON_OUTPUT_PATH}: {e}")
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
        logging.error("apktool not found. Cannot decompile APK.")
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
    """Detect vulnerability by checking getSharedPreferences + MODE_WORLD_WRITEABLE calls"""
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
        logging.error("[CRITICAL VULNERABILITY] Context.getSharedPreferences(..., MODE_WORLD_WRITEABLE) detected!")
        for api_name, callers in vulnerable_api_details.items():
            logging.error(f"\nVulnerable API: {api_name}")
            logging.error(f"Vulnerable Parameter: {TARGET_APIS[api_name]['vulnerable_param']}")
            logging.error(f"Called in {len(callers)} file(s):")
            for caller in callers:
                logging.error(f"  - File: {caller['smali_file']}")
                logging.error(f"    Line Numbers: {', '.join(map(str, caller['line_numbers']))}")

        logging.error(f"\nRisk Explanation:")
        logging.error(
            f"1. SharedPreferences stores critical app data (e.g., user authentication state, session tokens, permission flags, business logic parameters)")
        logging.error(f"2. MODE_WORLD_WRITEABLE (0x2) allows ALL apps on the device to modify these critical settings")
        logging.error(f"3. Catastrophic risks (higher than world-readable):")
        logging.error(f"   - Account hijacking: Tamper with 'isLogin' flag or user ID to impersonate legitimate users")
        logging.error(f"   - Permission bypass: Modify 'admin' or 'premium' flags to gain unauthorized privileges")
        logging.error(f"   - Application logic crash: Corrupt app configuration leading to denial of service")
        logging.error(
            f"   - Remote code execution: If the app uses preferences to control code execution (e.g., load external modules)")
        logging.error(f"   - Combined risk (0x3): Attackers can read + write preferences (full control over app state)")
        logging.error(f"4. Android version note:")
        logging.error(f"   - Android 4.2 (API 17+) deprecated MODE_WORLD_WRITEABLE/MODE_WORLD_READABLE")
        logging.error(
            f"   - Android 7.0 (API 24+) sandbox restricts access, but privileged apps can still exploit legacy vulnerabilities")
        logging.error(
            f"   - Android 10+ (API 29+) scoped storage does not mitigate this risk for app-specific preferences")

        logging.error(f"\nFix Recommendation:")
        logging.error(
            f"1. Urgently replace with safe mode: Use MODE_PRIVATE (0x0, default) instead of MODE_WORLD_WRITEABLE")
        logging.error(f"   - Code example: getSharedPreferences(\"my_prefs\", Context.MODE_PRIVATE);")
        logging.error(f"   - MODE_PRIVATE: Fully isolates the preferences file (only current app can read/write)")
        logging.error(
            f"2. Strictly ban world-writable modes: MODE_WORLD_WRITEABLE is deprecated and must not be used in any scenario")
        logging.error(f"3. Secure sensitive preferences with encryption:")
        logging.error(
            f"   - Mandatory for sensitive data: Use AndroidX Security library's EncryptedSharedPreferences (AES-256 encryption)")
        logging.error(
            f"   - Implementation: Encrypts keys and values transparently, preventing tampering even if file access is compromised")
        logging.error(
            f"   - Avoid storing high-risk data: Never store encryption keys, private certificates, or one-time tokens in preferences (use KeyStore)")
        logging.error(f"4. For legitimate data sharing (if required):")
        logging.error(
            f"   - Use ContentProvider with custom permissions and signature verification (only allow trusted apps to write)")
        logging.error(
            f"   - Implement data validation: Check the integrity of shared data (e.g., hash verification) before using it")
        logging.error(f"5. Remediate existing vulnerabilities:")
        logging.error(
            f"   - Audit all SharedPreferences files for tampering (check file modification time, hash values)")
        logging.error(f"   - Revoke compromised credentials (e.g., session tokens) if tampering is detected")
        logging.error(f"   - Push an emergency update to fix the mode and re-encrypt sensitive data")
        logging.error(f"6. Post-fix testing:")
        logging.error(f"   - Verify no other apps can access/write the preferences file via ADB or third-party tools")
        logging.error(f"   - Test edge cases (e.g., file corruption, tampered data) to ensure app stability")
        return True
    else:
        logging.info("[SAFE] No getSharedPreferences(..., MODE_WORLD_WRITEABLE) calls detected")
        logging.info(f"Target API: {list(TARGET_APIS.keys())[0]}")
        logging.info(
            f"Note: Use MODE_PRIVATE and encrypt sensitive data with EncryptedSharedPreferences for maximum security")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Detect getSharedPreferences(..., MODE_WORLD_WRITEABLE) Tampering Vulnerability (auto-save API map)")
    parser.add_argument("--serial", help="Specify ADB device serial (optional; auto-detect online devices)")
    args = parser.parse_args()

    # Get target devices
    devices = [args.serial] if args.serial else list_adb_devices()
    if not devices:
        logging.error("No online ADB devices detected. Ensure ADB is connected.")
        return False
    logging.info(f"Detected {len(devices)} online device(s): {devices}")

    # Process all devices
    overall_vulnerable = False
    for device in devices:
        if process_device(device):
            overall_vulnerable = True

    return overall_vulnerable


if __name__ == "__main__":
    main()
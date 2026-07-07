#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detect_insecure_securerandom_vuln.py

Detect Insecure SecureRandom Usage (setSeed Call) Vulnerability in CarSetting.apk
Vulnerability Description:
SecureRandom 是 Android 安全随机数生成器，若主动调用 setSeed 方法可能导致安全风险：
1. 若种子（seed）为固定值/弱随机性值（如时间戳、设备ID、硬编码字符串），会降低随机数熵值，易被预测
2. 若多次调用 setSeed 或种子来源不可信，可能破坏 SecureRandom 内部状态，导致生成的随机数可被破解
3. 安全场景（加密密钥、Token、IV 生成）中使用此类随机数，会导致敏感数据泄露或被篡改

Key Features:
1. 跳过系统/框架目录（加速扫描，不影响检测准确性）
2. 检测 SecureRandom.setSeed() 调用（含所有参数类型、重载方法）
3. 记录漏洞文件路径、行号和调用详情
4. 生成 JSON 格式漏洞报告
5. 兼容 Python 3.6+、多 dex APK
"""
POC_TAG = "34. 检测设备app是否使用了不安全的伪随机数生成..."

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
JSON_OUTPUT_PATH = os.path.join(os.getcwd(), "APIMap_CarSetting_InsecureSecureRandom.json")

# ==========================
# 加速关键配置：跳过系统/框架目录
# ==========================
SKIP_DIR_PATTERNS = [
    "smali/android/",
    "smali_classes2/android/",
    "smali_classes3/android/",
    "smali_classes4/android/",
    "smali/androidx/",
    "smali_classes2/androidx/",
    "smali_classes3/androidx/",
    "smali_classes4/androidx/",
    "smali/com/android/",
    "smali_classes2/com/android/",
    "smali_classes3/com/android/",
    "smali_classes4/com/android/",
    "smali/com/google/android/",
    "smali_classes2/com/google/android/",
    "smali/javax/",
    "smali/org/xml/",
    "smali/org/w3c/",
    "smali/java/lang/",
    "smali/java/util/",
]

# ==========================
# 漏洞特征：SecureRandom.setSeed() 调用（覆盖所有场景）
# 匹配规则：
# 1. 直接调用：new SecureRandom().setSeed(...) 或 secureRandomInstance.setSeed(...)
# 2. 重载方法：setSeed(long seed) 或 setSeed(byte[] seed)
# 3. 变量引用：如 sr.setSeed(...)、mSecureRandom.setSeed(...)
# 4. 链式调用：如 SecureRandom.getInstance(...).setSeed(...)
# ==========================
INSECURE_SECURERANDOM_PATTERNS = [
    # 匹配 new SecureRandom().setSeed(...)
    re.compile(r'new\s+SecureRandom\s*\(\s*\)\s*\.\s*setSeed\s*\(', re.IGNORECASE), re.compile(r'\w+\s*\.\s*setSeed\s*\(', re.IGNORECASE),re.compile(r'SecureRandom\s*\.\s*getInstance\s*\(.+?\)\s*\.\s*setSeed\s*\(', re.IGNORECASE),
re.compile(r'\(\s*SecureRandom\s*\)\s*.+?\s*\.\s*setSeed\s*\(', re.IGNORECASE),
]


RISKY_SEED_PATTERNS = [
 # 时间戳种子（如 System.currentTimeMillis()、System.nanoTime()）
re.compile(r'System\.currentTimeMillis\(\)', re.IGNORECASE),
re.compile(r'System\.nanoTime\(\)', re.IGNORECASE),
# 设备相关种子（如 Build.SERIAL、android_id）
re.compile(r'Build\.[A-Z_]+', re.IGNORECASE),
re.compile(r'android_id', re.IGNORECASE),
re.compile(r'device_id', re.IGNORECASE),
# 硬编码字符串/数字种子
re.compile(r'"[^"]*"'),  # 字符串常量
re.compile(r'\d+L?'),  # 数字常量（含长整型）
# 简单随机数种子（如 new Random().nextLong()）
re.compile(r'new\s+Random\s*\(\s*\)\s*\.\s*next', re.IGNORECASE),
]

TARGET_INFO = {
    "Insecure SecureRandom Usage": {
        "vulnerable_feature": "SecureRandom.setSeed() method call",
        "risk_seed_patterns": [p.pattern for p in RISKY_SEED_PATTERNS],
        "safe_usage": [
            "Use SecureRandom without calling setSeed (rely on system-provided seed)",
            "If seed is required, use high-entropy seed (e.g., hardware randomness, encrypted user input)",
            "Use AndroidKeyStore to generate secure random numbers for encryption"
        ]
    }
}

# Type alias for result map
ResultMap = Dict[str, List[Dict[str, Union[str, List[int], List[str]]]]]


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


def should_skip_dir(dir_path: str) -> bool:
    """判断是否需要跳过当前目录"""
    dir_path_lower = dir_path.lower()
    for pattern in SKIP_DIR_PATTERNS:
        if pattern.lower() in dir_path_lower:
            return True
    return False


def analyze_seed_risk(line_content: str) -> List[str]:
    """分析种子的风险特征，返回匹配的风险类型"""
    risky_features = []
    for idx, pattern in enumerate(RISKY_SEED_PATTERNS):
        if pattern.search(line_content):
            if idx == 0 or idx == 1:
                risky_features.append("Timestamp-based seed (low entropy)")
            elif idx == 2 or idx == 3 or idx == 4:
                risky_features.append("Device-related seed (predictable)")
            elif idx == 5 or idx == 6:
                risky_features.append("Hardcoded seed (completely predictable)")
            elif idx == 7:
                risky_features.append("Random-class seed (weak entropy)")
    return risky_features


def scan_smali_for_insecure_securerandom(smali_root_list: List[str]) -> ResultMap:
    """Scan smali files for insecure SecureRandom usage (跳过系统目录加速)"""
    result: ResultMap = {"Insecure SecureRandom Usage": []}
    total_files_scanned = 0
    skipped_files = 0
    skipped_dirs = 0

    for smali_root in smali_root_list:
        for root, dirs, files in os.walk(smali_root):
            # 跳过系统目录
            if should_skip_dir(root):
                skipped_dirs += 1
                dirs[:] = []
                continue

            # 扫描当前目录下的 smali 文件
            for file in fnmatch.filter(files, "*.smali"):
                total_files_scanned += 1
                smali_path = os.path.join(root, file)
                try:
                    with open(smali_path, "r", encoding="utf-8", errors="ignore") as f:
                        smali_lines = f.read().splitlines()

                        matched_lines = []
                        line_details = {}  # key: 行号, value: (调用内容, 风险特征)

                        for line_idx, line in enumerate(smali_lines, 1):
                            # 检查是否存在 setSeed 调用
                            for pattern in INSECURE_SECURERANDOM_PATTERNS:
                                if pattern.search(line):
                                    # 提取调用内容（简化显示）
                                    call_content = line.strip()[:100]  # 截取前100字符避免过长
                                    # 分析种子风险
                                    risky_features = analyze_seed_risk(line)
                                    # 记录行信息
                                    matched_lines.append(line_idx)
                                    line_details[line_idx] = (call_content, risky_features)
                                    break  # 一个行匹配一个模式即可

                        # 若有匹配结果，添加到结果中
                        if matched_lines:
                            matched_lines = sorted(list(set(matched_lines)))
                            # 构建详细信息
                            details = []
                            for line_num in matched_lines:
                                call_content, risky_features = line_details[line_num]
                                details.append({
                                    "line_number": line_num,
                                    "call_content": call_content,
                                    "risky_seed_features": risky_features or [
                                        "No obvious risky seed (still need audit)"]
                                })

                            # 检查文件是否已存在，避免重复
                            file_exists = False
                            for entry in result["Insecure SecureRandom Usage"]:
                                if entry["smali_file"] == smali_path:
                                    entry["details"].extend(details)
                                    file_exists = True
                                    break
                            if not file_exists:
                                result["Insecure SecureRandom Usage"].append({
                                    "smali_file": smali_path,
                                    "details": details
                                })
                except Exception as e:
                    logging.warning(f"Failed to read smali file: {smali_path} (error: {e})")
                    skipped_files += 1
                    continue

    # 输出扫描统计
    logging.info(f"\nScan Statistics:")
    logging.info(f"- Total smali files scanned: {total_files_scanned}")
    logging.info(f"- Skipped directories (system/framework): {skipped_dirs}")
    logging.info(f"- Skipped files (read error): {skipped_files}")
    logging.info(f"- Vulnerable files found: {len(result['Insecure SecureRandom Usage'])}")
    return result


def save_result_map(result_map: ResultMap) -> bool:
    """Save vulnerability report to JSON file"""
    try:
        output_data = {
            "description": "Insecure SecureRandom Usage (setSeed Call) Vulnerability Detection Result",
            "scan_config": {
                "skipped_dir_patterns": SKIP_DIR_PATTERNS,
                "vulnerable_patterns": [p.pattern for p in INSECURE_SECURERANDOM_PATTERNS],
                "risk_seed_patterns": [p.pattern for p in RISKY_SEED_PATTERNS]
            },
            "target_info": TARGET_INFO["Insecure SecureRandom Usage"],
            "vulnerable_entries": result_map["Insecure SecureRandom Usage"]
        }
        with open(JSON_OUTPUT_PATH, "w", encoding="utf-8") as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)
        logging.info(f"\nVulnerability report saved to: {JSON_OUTPUT_PATH}")
        return True
    except Exception as e:
        logging.error(f"Failed to save vulnerability report: {e}")
        return False


def get_or_create_decoded_folder(apk_path: str, device: str) -> Optional[str]:
    """Reuse existing decoded folder or create new one"""
    existing_decoded = find_existing_decoded_folder()
    if existing_decoded:
        return existing_decoded

    device_safe = device.replace(":", "_")
    new_decoded_dir = os.path.join(os.getcwd(), f"{DECODED_FOLDER_PREFIX}{device_safe}")
    logging.info(f"Preparing to decode APK to: {new_decoded_dir}")

    at_cmd = apktool_cmd()
    if not at_cmd:
        logging.error("apktool not found. Cannot decompile APK.")
        return None

    if os.path.exists(new_decoded_dir):
        logging.info(f"Deleting old decoded folder: {new_decoded_dir}")
        try:
            shutil.rmtree(new_decoded_dir)
        except Exception as e:
            logging.warning(f"Failed to delete old decoded folder: {e}")
            return None

    if try_apktool_decode(apk_path, new_decoded_dir, at_cmd):
        return new_decoded_dir
    else:
        logging.error("Failed to create new decoded folder")
        return None


def process_device(device: str) -> bool:
    """Process single device: get APK → decode → scan → report"""
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

    # Step 3: Collect smali directories
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

    # Step 4: Scan for insecure SecureRandom
    logging.info(f"Scanning smali files for insecure SecureRandom usage (skipping system directories)...")
    result_map = scan_smali_for_insecure_securerandom(smali_root_list)
    vulnerable_entries = result_map["Insecure SecureRandom Usage"]

    # Step 5: Save report
    if not save_result_map(result_map):
        logging.error("Failed to save vulnerability report")

    # Step 6: Output result
    logging.info(f"\n===== Vulnerability Detection Result =====")
    if vulnerable_entries:
        logging.error("[HIGH VULNERABILITY] Insecure SecureRandom Usage (setSeed Call) Detected!")
        for entry in vulnerable_entries:
            logging.error(f"\nVulnerable File: {entry['smali_file']}")
            for detail in entry["details"]:
                logging.error(f"  Line {detail['line_number']}: {detail['call_content']}")
                logging.error(f"  Risk Features: {', '.join(detail['risky_seed_features'])}")

        logging.error(f"\nRisk Explanation:")
        logging.error(f"1. SecureRandom 设计原则：依赖系统提供的高熵种子（如硬件随机数、系统环境变量），主动调用 setSeed 可能破坏其安全性：")
        logging.error(f"   - 固定/弱熵种子：导致随机数可预测（如时间戳种子仅能提供毫秒级随机性，易被暴力破解）")
        logging.error(f"   - 种子污染：多次调用 setSeed 可能覆盖系统安全种子，降低整体熵值")
        logging.error(f"   - 状态破坏：不当种子可能导致 SecureRandom 内部状态退化，生成重复序列")
        logging.error(f"2. 典型风险场景：")
        logging.error(f"   - 加密密钥生成：使用可预测随机数 → 密钥被破解 → 敏感数据泄露")
        logging.error(f"   - Token/IV 生成：重复 IV 导致 AES-CBC 模式漏洞（如 BEAST 攻击）")
        logging.error(f"   - 验证码生成：可预测验证码 → 账号被盗")
        logging.error(f"3. 例外情况（合法使用场景极少）：")
        logging.error(f"   - 仅当种子为高熵、不可预测且仅调用一次时（如硬件随机数生成器输出），setSeed 才可能安全")
        logging.error(f"   - 普通业务场景几乎无合法使用需求，99% 的 setSeed 调用均为不安全用法")

        logging.error(f"\nFix Recommendation:")
        logging.error(f"1. 优先方案：移除所有 setSeed 调用，依赖 SecureRandom 默认种子机制：")
        logging.error(f"   - 错误用法：new SecureRandom().setSeed(System.currentTimeMillis()); // 弱熵种子")
        logging.error(f"   - 正确用法：new SecureRandom(); // 依赖系统高熵种子（推荐）")
        logging.error(f"2. 若必须指定种子（极特殊场景）：")
        logging.error(f"   - 种子必须是高熵、不可预测的（如：Hardware-backed 随机数、用户加密输入+盐值）")
        logging.error(f"   - 仅调用一次 setSeed，且不与系统默认种子冲突（可通过 SecureRandom(byte[] seed) 构造函数传入）")
        logging.error(f"   - 禁止使用：时间戳、设备ID、硬编码字符串、Random 类输出作为种子")
        logging.error(f"3. 安全随机数生成最佳实践：")
        logging.error(
            f"   - 加密场景：使用 AndroidKeyStore 生成随机数（如 KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, \"AndroidKeyStore\")）")
        logging.error(f"   - 普通场景：SecureRandom.getInstanceStrong()（Android 8.0+，强制使用高熵源）")
        logging.error(f"   - 兼容场景：SecureRandom.getInstance(\"SHA1PRNG\", \"Crypto\")（需确保无 setSeed 调用）")
        logging.error(f"4. 代码审计要点：")
        logging.error(f"   - 检查所有 SecureRandom 实例的 setSeed 调用，确认种子来源是否安全")
        logging.error(f"   - 替换弱种子：若必须使用种子，改为高熵种子（如 PBKDF2 派生的密钥+随机盐值）")
        logging.error(f"   - 测试验证：使用随机数检测工具（如 NIST SP 800-22）验证输出随机性")
        logging.error(f"5. 修复示例：")
        logging.error(f"   // 不安全代码")
        logging.error(f"   SecureRandom sr = new SecureRandom();")
        logging.error(f"   sr.setSeed(System.currentTimeMillis()); // 弱熵种子")
        logging.error(f"   byte[] key = new byte[16];")
        logging.error(f"   sr.nextBytes(key); // 可预测密钥")
        logging.error(f"   ")
        logging.error(f"   // 安全代码")
        logging.error(f"   SecureRandom sr = new SecureRandom(); // 无 setSeed 调用")
        logging.error(f"   byte[] key = new byte[16];")
        logging.error(f"   sr.nextBytes(key); // 高熵密钥")
        return True
    else:
        logging.info("[SAFE] No Insecure SecureRandom Usage Detected")
        logging.info(f"Note: Ensure all SecureRandom instances do not call setSeed with weak seeds")
        return False


def run_check():
    parser = argparse.ArgumentParser(
        description="Detect Insecure SecureRandom Usage (setSeed Call) Vulnerability (Fast Version: Skip System Directories)")
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

    overall_vulnerable



# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc34PseudoRandPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测设备app是否使用了不安全的伪随机数生成...'
    meta_cve_id = 'CWE-338'
    meta_severity = 'Medium'
    meta_protocol = 'crypto'
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

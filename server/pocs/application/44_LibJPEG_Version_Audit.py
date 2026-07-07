#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detect_libjpeg_turbo_cve2018_1152.py

检测系统或 APK 中是否使用了 ≤ 1.5.90 的 libjpeg-turbo.so 库（CVE-2018-1152 DOS 漏洞）：
1) 设备端检查常见路径的 libjpeg-turbo.so（adb 已连接）；
2) 本地扫描 APK 文件，提取内置的 libjpeg-turbo.so；
3) 通过二进制文件提取版本号，判断是否 ≤ 1.5.90。

用法:
  python detect_libjpeg_turbo_cve2018_1152.py
  python detect_libjpeg_turbo_cve2018_1152.py --serial <device>
"""

POC_TAG = "45. 检测系统或app是否使用了不安全的libjpeg-turbo.so库（CVE-2018-1152）..."


from typing import List, Optional, Tuple
import argparse
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

ADB_CMD = "adb"
TARGET_VER = (1, 5, 91)  # 阈值：≤1.5.90 判定为漏洞版本（1.5.91 及以上修复）
# 车机/安卓系统常见 libjpeg-turbo.so 路径
DEVICE_PATHS = [
    "/system/lib/libjpeg-turbo.so",
    "/system/lib64/libjpeg-turbo.so",
    "/vendor/lib/libjpeg-turbo.so",
    "/vendor/lib64/libjpeg-turbo.so",
    "/system/lib/libjpeg-turbo.so.0",  # 部分系统带版本后缀
    "/system/lib64/libjpeg-turbo.so.0"
]
APK_GLOB = "*.apk"
# 优化版本正则：支持 x.y.z、x.y.z0 等格式，且优先匹配 libjpeg-turbo 相关版本
VERSION_REGEX = re.compile(r"(libjpeg-turbo-|version |VER=)?(\d{1,3}\.\d{1,3}\.\d{1,3})", re.IGNORECASE)


def run_cmd(cmd: List[str], timeout: float = 15.0) -> Tuple[int, str]:
    """执行命令并返回状态码和输出"""
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        out = proc.stdout or proc.stderr or b""
        try:
            txt = out.decode("utf-8", errors="ignore")
        except Exception:
            txt = out.decode("latin-1", errors="ignore")
        return proc.returncode, txt.strip()
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    except FileNotFoundError as e:
        return -2, f"command not found: {e}"
    except Exception as e:
        return -3, str(e)


def list_adb_devices() -> List[str]:
    """获取已连接的 ADB 设备列表"""
    code, out = run_cmd([ADB_CMD, "devices"], timeout=4.0)
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


def device_file_exists(device: Optional[str], path: str) -> bool:
    """检查设备上文件是否存在"""
    cmd = [ADB_CMD]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "ls", path]
    code, out = run_cmd(cmd, timeout=6.0)
    if code < 0:
        return False
    if "No such file" in out or "没有那个文件或目录" in out:
        return False
    return True


def adb_pull_to(device: Optional[str], remote: str, local: str) -> bool:
    """从设备拉取文件到本地"""
    cmd = [ADB_CMD]
    if device:
        cmd += ["-s", device]
    cmd += ["pull", remote, local]
    code, out = run_cmd(cmd, timeout=30.0)
    return code == 0 and os.path.exists(local) and os.path.getsize(local) > 0


def extract_ascii_sequences_from_file(path: str, min_len: int = 4) -> List[str]:
    """从二进制文件中提取可打印 ASCII 字符串"""
    seqs = []
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        logging.warning(f"read file failed: {e}")
        return seqs
    current = bytearray()
    for b in data:
        if 32 <= b <= 126:  # 可打印 ASCII 范围
            current.append(b)
        else:
            if len(current) >= min_len:
                try:
                    seqs.append(current.decode("utf-8", errors="ignore"))
                except Exception:
                    seqs.append(current.decode("latin-1", errors="ignore"))
            current = bytearray()
    # 处理文件末尾的字符串
    if len(current) >= min_len:
        try:
            seqs.append(current.decode("utf-8", errors="ignore"))
        except Exception:
            seqs.append(current.decode("latin-1", errors="ignore"))
    return seqs


def find_version_in_binary(path: str) -> Optional[str]:
    """从二进制文件中提取 libjpeg-turbo 版本号"""
    seqs = extract_ascii_sequences_from_file(path, min_len=4)
    for s in seqs:
        # 优先匹配包含 libjpeg-turbo 标识的版本字符串
        match = VERSION_REGEX.search(s)
        if match:
            ver = match.group(2)
            # 验证版本格式（x.y.z）
            parts = ver.split('.')
            if len(parts) == 3 and all(p.isdigit() for p in parts):
                logging.info(f"extracted version: {ver} from {path}")
                return ver
    # 若未找到带标识的版本，尝试匹配纯 x.y.z 格式
    for s in seqs:
        for m in re.finditer(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\b", s):
            ver = m.group()
            parts = ver.split('.')
            if len(parts) == 3 and all(p.isdigit() for p in parts):
                logging.info(f"extracted version (fallback): {ver} from {path}")
                return ver
    return None


def version_tuple(ver_str: str) -> Tuple[int, int, int]:
    """将版本字符串转为元组（用于比较）"""
    parts = ver_str.split('.')
    # 补全为 3 位（如 1.5 → (1,5,0)）
    parts = (parts + ['0', '0'])[:3]
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except Exception:
        return (0, 0, 0)


def is_vulnerable_version(ver_str: Optional[str]) -> Optional[bool]:
    """判断版本是否存在漏洞（≤1.5.90 为漏洞版本）"""
    if not ver_str:
        return None
    tup = version_tuple(ver_str)
    return tup < TARGET_VER  # TARGET_VER 是 (1,5,91)，故 ≤1.5.90 返回 True


def check_device_paths(device: Optional[str], tmpdir: str) -> List[dict]:
    """检查设备上的 libjpeg-turbo.so 并检测版本"""
    results = []
    for p in DEVICE_PATHS:
        entry = {
            "path": p,
            "exists": False,
            "local": None,
            "version": None,
            "vulnerable": None
        }
        if device_file_exists(device, p):
            entry["exists"] = True
            # 本地保存路径（避免文件名冲突）
            local_name = f"{os.path.basename(p).replace('/', '_')}_{device or 'default'}"
            local_path = os.path.join(tmpdir, local_name)
            if adb_pull_to(device, p, local_path):
                entry["local"] = local_path
                entry["version"] = find_version_in_binary(local_path)
                entry["vulnerable"] = is_vulnerable_version(entry["version"])
                logging.warning(
                    f"设备 {device or '未知设备'}: 找到 {p} → 本地路径: {local_path} "
                    f"| 版本: {entry['version']} | 存在漏洞: {entry['vulnerable']}"
                )
            else:
                logging.warning(f"设备 {device or '未知设备'}: 文件 {p} 存在但拉取失败")
        else:
            logging.info(f"设备 {device or '未知设备'}: 未找到 {p}")
        results.append(entry)
    return results


def scan_local_apks_for_libs(cwd: str, tmpdir: str) -> List[dict]:
    """扫描本地 APK 中的 libjpeg-turbo.so"""
    results = []
    for fname in os.listdir(cwd):
        if not fname.lower().endswith(".apk"):
            continue
        apk_path = os.path.join(cwd, fname)
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for zi in zf.namelist():
                    # 匹配 APK 中 lib 目录下的 libjpeg-turbo.so（支持不同架构和后缀）
                    if "libjpeg-turbo.so" in zi and (zi.startswith("lib/") or "lib/" in zi):
                        # 提取到临时目录
                        local_name = f"{os.path.splitext(fname)[0]}_{os.path.basename(zi)}"
                        local_path = os.path.join(tmpdir, local_name)
                        try:
                            with zf.open(zi) as src, open(local_path, "wb") as dst:
                                shutil.copyfileobj(src, dst)
                            # 检测版本
                            ver = find_version_in_binary(local_path)
                            vuln = is_vulnerable_version(ver)
                            logging.warning(
                                f"APK {fname}: 找到 {zi} → 提取路径: {local_path} "
                                f"| 版本: {ver} | 存在漏洞: {vuln}"
                            )
                            results.append({
                                "apk": apk_path,
                                "lib_in_apk": zi,
                                "extracted": local_path,
                                "version": ver,
                                "vulnerable": vuln
                            })
                        except Exception as e:
                            logging.warning(f"APK {fname}: 提取 {zi} 失败: {e}")
        except zipfile.BadZipFile:
            logging.warning(f"{apk_path} 不是合法 APK 文件")
        except Exception as e:
            logging.warning(f"读取 APK {apk_path} 失败: {e}")
    return results


def run_check():
    parser = argparse.ArgumentParser(description="CVE-2018-1152 漏洞检测（libjpeg-turbo ≤1.5.90）")
    parser.add_argument("--serial", help="ADB 设备序列号（可选，未指定则自动检测已连接设备）")
    args = parser.parse_args()

    # 获取目标设备列表
    devices = [args.serial] if args.serial else list_adb_devices()
    if args.serial and args.serial not in devices:
        logging.warning(f"指定设备 {args.serial} 未连接，仅扫描本地 APK")
        devices = []

    # 创建临时目录（用于存放拉取/提取的 .so 文件）
    tmpdir = tempfile.mkdtemp(prefix="libjpeg_turbo_check_")
    logging.info(f"临时目录: {tmpdir}")
    overall_vulns = []

    # 1. 检测设备上的 libjpeg-turbo.so
    if devices:
        for dev in devices:
            logging.warning(f"\n===== 开始检测设备: {dev} =====")
            dev_results = check_device_paths(dev, tmpdir)
            for r in dev_results:
                if r["vulnerable"] is True:
                    overall_vulns.append(("device", dev, r))
    else:
        logging.warning("\n未找到已连接的 ADB 设备，跳过设备检测")

    # 2. 扫描本地 APK
    logging.warning(f"\n===== 开始扫描本地 APK（当前目录: {os.getcwd()}）=====")
    local_results = scan_local_apks_for_libs(os.getcwd(), tmpdir)
    for r in local_results:
        if r["vulnerable"] is True:
            overall_vulns.append(("apk", r["apk"], r))

    # 清理临时目录
    if os.path.exists(tmpdir):
        shutil.rmtree(tmpdir)
        logging.info(f"临时目录 {tmpdir} 已清理")

    # 输出漏洞汇总
    logging.warning("\n" + "="*60)
    if overall_vulns:
        logging.warning(" 发现漏洞版本（CVE-2018-1152）：")
        for kind, src, info in overall_vulns:
            if kind == "device":
                logging.warning(f"设备: {src} | 路径: {info['path']} | 版本: {info['version']}")
            else:
                logging.warning(f"APK: {src} | 内置库: {info['lib_in_apk']} | 版本: {info['version']}")
        logging.warning("\n修复建议：")
        logging.warning("1. 联系车机厂商推送系统更新，将 libjpeg-turbo 升级至 1.5.91 及以上版本；")
        logging.warning("2. 替换 APK 中内置的漏洞版本库，使用修复版 libjpeg-turbo.so；")
        logging.warning("3. 限制不可信 JPEG 图片来源，避免触发 DOS 攻击。")
        return True
    else:
        logging.warning(" 未发现漏洞版本的 libjpeg-turbo.so")
        return False

    logging.warning("="*60)



# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc45LibjepgExportedPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测系统或app是否使用了不安全的libjpeg-turbo.so库（CVE-2018-1152）...'
    meta_cve_id = 'CVE-2018-1152'
    meta_severity = 'High'
    meta_protocol = 'native'
    meta_target_os = ['android', 'linux']
    meta_required_params = ['expected_usb_serial']
    meta_profiles = ['local_artifact']
    meta_attack_surface = '第三方组件/高级漏洞'
    is_disruptive = False
    meta_destructive_level = 'Probe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

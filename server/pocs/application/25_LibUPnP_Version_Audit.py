#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detect_libupnp_version.py

检测系统或 APK 中是否使用了低于 1.6.18 的 libupnp.so 库：
1) 在设备上检查下列路径（假定 adb 已连接）：
   /system/lib/libupnp.so
   /system/lib64/libupnp.so
   /vendor/lib/libupnp.so
   如果存在则 pull 到本机并检测版本号（从二进制中提取 ASCII 版本号样式 x.y.z）
   若检测到版本 < 1.6.18，则报告为 Vulnerable。

2) 若设备上未发现上述文件或需要额外检查，则在当前目录下查找所有 *.apk：
   - 对每个 apk 打开 zip，查找 lib/**/libupnp.so
   - 若存在则提取并检查版本（同上）

实现说明：
- 从二进制中提取可打印 ASCII 序列并用正则搜索形如 1.6.17 的版本号。
- 若找到多个版本号，优先返回最符合语义版本格式的项（先出现者）。
- 若无法解析出版本号，则标记为 Unknown（不可确定）。
- 输出统一使用 logging.warning（按你的要求）。
- 不做任何破坏性操作。

用法:
  python detect_libupnp_version.py
  python detect_libupnp_version.py --serial <device>
"""
POC_TAG = "20. 检测系统或app是否使用了不安全的libupnp.so库（CVE-2016-8863）..."

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
import shutil
import os

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

ADB_CMD = "adb"
TARGET_VER = (1, 6, 18)  # threshold: versions < TARGET_VER are considered vulnerable
DEVICE_PATHS = [
    "/system/lib/libupnp.so",
    "/system/lib64/libupnp.so",
    "/vendor/lib/libupnp.so"
]
APK_GLOB = "*.apk"
VERSION_REGEX = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\b")  # basic x.y.z


def run_cmd(cmd: List[str], timeout: float = 15.0) -> Tuple[int, str]:
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        out = proc.stdout or proc.stderr or b""
        try:
            txt = out.decode("utf-8", errors="ignore")
        except Exception:
            txt = out.decode("latin-1", errors="ignore")
        return proc.returncode, txt.strip()
    except subprocess.TimeoutExpired:
        return -1, ""
    except FileNotFoundError as e:
        return -2, str(e)
    except Exception as e:
        return -3, str(e)


def list_adb_devices() -> List[str]:
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
    cmd = [ADB_CMD]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "ls", path]
    code, out = run_cmd(cmd, timeout=6.0)
    if code < 0:
        return False
    if "No such file" in out or "没有那个文件或目录" in out:
        return False
    # treat any other output as existence
    return True


def adb_pull_to(device: Optional[str], remote: str, local: str) -> bool:
    cmd = [ADB_CMD]
    if device:
        cmd += ["-s", device]
    cmd += ["pull", remote, local]
    code, out = run_cmd(cmd, timeout=30.0)
    return code == 0 and os.path.exists(local) and os.path.getsize(local) > 0


def extract_ascii_sequences_from_file(path: str, min_len: int = 4) -> List[str]:
    """
    从二进制文件中提取可打印 ASCII 子串，长度 >= min_len
    返回这些子串（顺序为出现顺序）
    """
    seqs = []
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        return seqs
    current = bytearray()
    for b in data:
        if 32 <= b <= 126:  # printable
            current.append(b)
        else:
            if len(current) >= min_len:
                try:
                    seqs.append(current.decode("utf-8", errors="ignore"))
                except Exception:
                    seqs.append(current.decode("latin-1", errors="ignore"))
            current = bytearray()
    if len(current) >= min_len:
        try:
            seqs.append(current.decode("utf-8", errors="ignore"))
        except Exception:
            seqs.append(current.decode("latin-1", errors="ignore"))
    return seqs


def find_version_in_binary(path: str) -> Optional[str]:
    """
    在二进制文件中查找第一个语义版本 x.y.z，返回字符串或 None
    """
    # First try to run `strings` if available (faster on big files), else fallback to python extraction
    # But to avoid external dependency we use python extraction
    seqs = extract_ascii_sequences_from_file(path, min_len=4)
    for s in seqs:
        for m in VERSION_REGEX.finditer(s):
            ver = m.group(1)
            # basic sanity: components numeric and reasonable
            parts = ver.split('.')
            if len(parts) == 3:
                try:
                    nums = tuple(int(p) for p in parts)
                    # ignore absurd versions (e.g., 0.0.0?) still allow though
                    return ver
                except Exception:
                    continue
    return None


def version_tuple(ver_str: str) -> Tuple[int, int, int]:
    parts = ver_str.split('.')
    parts = (parts + ['0','0'])[:3]
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except Exception:
        return (0, 0, 0)


def is_vulnerable_version(ver_str: Optional[str]) -> Optional[bool]:
    """
    判断版本字符串是否低于 TARGET_VER
    返回 True (vulnerable) / False (not) / None (unknown)
    """
    if not ver_str:
        return None
    tup = version_tuple(ver_str)
    return tup < TARGET_VER


def check_device_paths(device: Optional[str], tmpdir: str) -> List[dict]:
    """
    检查设备上预定义路径，pull 并检测版本
    返回结果列表 dict { path, exists, local_copy, version, vulnerable (True/False/None) }
    """
    results = []
    for p in DEVICE_PATHS:
        entry = {"path": p, "exists": False, "local": None, "version": None, "vulnerable": None}
        if device_file_exists(device, p):
            entry["exists"] = True
            local = os.path.join(tmpdir, os.path.basename(p).replace('/', '_'))
            ok = adb_pull_to(device, p, local)
            if ok:
                entry["local"] = local
                ver = find_version_in_binary(local)
                entry["version"] = ver
                entry["vulnerable"] = is_vulnerable_version(ver)
                logging.warning(f"{device or 'device'}: pulled {p} -> {local}; version={ver}; vulnerable={entry['vulnerable']}")
            else:
                logging.warning(f"{device or 'device'}: file {p} exists but pull failed")
        else:
            logging.warning(f"{device or 'device'}: file {p} not present")
        results.append(entry)
    return results


def scan_local_apks_for_libs(cwd: str, tmpdir: str) -> List[dict]:
    """
    扫描当前目录所有 apk 文件, 查找 lib/**/libupnp.so 并提取检测版本
    返回结果列表 dict { apk, libpath_in_apk, extracted_local, version, vulnerable }
    """
    results = []
    for fname in os.listdir(cwd):
        if not fname.lower().endswith(".apk"):
            continue
        apk_path = os.path.join(cwd, fname)
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for zi in zf.namelist():
                    # lib/<abi>/libupnp.so or similar
                    if zi.endswith("/libupnp.so") or zi.endswith("\\libupnp.so") or zi.endswith("libupnp.so"):
                        # extract to tmp
                        local_name = f"{os.path.splitext(fname)[0]}_{os.path.basename(zi)}"
                        local_path = os.path.join(tmpdir, local_name)
                        try:
                            with zf.open(zi) as src, open(local_path, "wb") as dst:
                                shutil.copyfileobj(src, dst)
                            ver = find_version_in_binary(local_path)
                            vuln = is_vulnerable_version(ver)
                            logging.warning(f"apk {fname}: found {zi}; extracted to {local_path}; version={ver}; vulnerable={vuln}")
                            results.append({
                                "apk": apk_path,
                                "lib_in_apk": zi,
                                "extracted": local_path,
                                "version": ver,
                                "vulnerable": vuln
                            })
                        except Exception as e:
                            logging.warning(f"apk {fname}: failed to extract {zi}: {e}")
        except zipfile.BadZipFile:
            logging.warning(f"file {apk_path} is not a valid zip/apk")
        except Exception as e:
            logging.warning(f"error opening {apk_path}: {e}")
    return results


def run_check():
    parser = argparse.ArgumentParser(description="检测系统或 apk 中 libupnp.so 版本是否低于 1.6.18")
    parser.add_argument("--serial", help="adb device serial (optional)")
    args = parser.parse_args()

    devices = [args.serial] if args.serial else list_adb_devices()
    # If serial provided but not connected, still allow local APK scan
    if args.serial and not devices:
        logging.warning(f"specified device {args.serial} not found online; will still scan local APKs")
        devices = []

    tmpdir = tempfile.mkdtemp(prefix="libupnp_check_")
    overall_vulns = []

    # If a device is available, check device paths for each device
    for dev in devices:
        logging.warning(f"checking device: {dev}")
        dev_results = check_device_paths(dev, tmpdir)
        for r in dev_results:
            if r.get("vulnerable") is True:
                overall_vulns.append(("device", dev, r))
    # If none found on device OR even if found, also scan local APKs per requirement
    logging.warning("scanning local APKs in current directory for libupnp.so...")
    local_results = scan_local_apks_for_libs(os.getcwd(), tmpdir)
    for r in local_results:
        if r.get("vulnerable") is True:
            overall_vulns.append(("apk", r.get("apk"), r))


    if os.path.exists(tmpdir) and os.path.isdir(tmpdir):
        shutil.rmtree(tmpdir)
        logging.warning(f"Folder {tmpdir} deleted successfully")
    else:
        logging.warning(f"Folder {tmpdir} does not exist or is not a directory")


    # Summary
    if not overall_vulns:
        logging.warning("no vulnerable libupnp.so (< 1.6.18) found on checked locations")
        return False
    else:
        logging.warning("VULNERABILITIES FOUND:")
        for kind, src, info in overall_vulns:
            if kind == "device":
                logging.warning(f"device {src} path {info['path']} version={info['version']}")
            else:
                logging.warning(f"apk {src} lib {info['lib_in_apk']} version={info['version']} extracted={info['extracted']}")
        return True





# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc20LibupnpExportPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测系统或app是否使用了不安全的libupnp.so库（CVE-2016-8863）...'
    meta_cve_id = 'CVE-2016-8863'
    meta_severity = 'High'
    meta_protocol = 'upnp'
    meta_target_os = ['android']
    meta_required_params = ['target_ip']
    meta_profiles = ['network']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = 'Probe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

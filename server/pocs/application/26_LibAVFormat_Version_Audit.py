#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detect_cve_2016_1897.py

检测系统或 APK 中是否使用了受 CVE-2016-1897 影响的 libavformat.so 版本
（受影响版本范围，按 minor 分支）：
 - 2.8.x where patch < 5
 - 2.7.x where patch < 5
 - 2.6.x where patch < 7
 - 2.5.x where patch < 10

流程：
1) 检查设备（如果有）上的预定义路径并尝试 pull 到本地分析
2) 扫描当前目录下的所有 APK，寻找 lib/**/libavformat.so 并提取分析
3) 输出以 logging.warning 显示检测结果与摘要

注意：
- 脚本只做只读检测与分析；不会修改目标设备或 APK。
- 版本提取基于二进制中的可打印字符串，结果有一定的不确定性（若无法解析到版本将标记为 Unknown）。
"""
POC_TAG = "21. 检测系统或app是否使用了不安全的libavformat.so库-v1（CVE-2016-1897）..."

from typing import List, Optional, Tuple, Dict
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
DEVICE_PATHS = [
    "/system/lib/libavformat.so",
    "/system/lib64/libavformat.so",
    "/vendor/lib/libavformat.so"
]

# Vulnerable thresholds by minor version: patch must be < threshold to be vulnerable
VULN_THRESHOLDS = {
    8: 5,   # 2.8.x  patch < 5
    7: 5,   # 2.7.x  patch < 5
    6: 7,   # 2.6.x  patch < 7
    5: 10   # 2.5.x  patch < 10
}

# Version regex: capture "2.<minor>.<patch>" where minor is 5..8
VERSION_REGEX = re.compile(r'\b2\.(5|6|7|8)\.(\d{1,4})\b')

# A broader regex to capture x.y.z as fallback
GENERIC_VERSION_RE = re.compile(r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,4})\b')

# For extracting printable sequences
MIN_PRINTABLE_SEQ_LEN = 4


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
    return True


def adb_pull_to(device: Optional[str], remote: str, local: str) -> bool:
    cmd = [ADB_CMD]
    if device:
        cmd += ["-s", device]
    cmd += ["pull", remote, local]
    code, out = run_cmd(cmd, timeout=30.0)
    return code == 0 and os.path.exists(local) and os.path.getsize(local) > 0


def extract_ascii_sequences_from_file(path: str, min_len: int = MIN_PRINTABLE_SEQ_LEN) -> List[str]:
    seqs: List[str] = []
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        return seqs
    current = bytearray()
    for b in data:
        if 32 <= b <= 126:
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
    在二进制文件中寻找合适的版本字符串，优先匹配 2.[5-8].patch 模式
    返回第一个匹配到的版本字符串，如 '2.8.4' 或 None
    """
    # 先用 quick python-based extraction
    seqs = extract_ascii_sequences_from_file(path, min_len=MIN_PRINTABLE_SEQ_LEN)
    for s in seqs:
        for m in VERSION_REGEX.finditer(s):
            minor = int(m.group(1))
            patch = int(m.group(2))
            return f"2.{minor}.{patch}"
    # fallback: try any x.y.z and accept if major==2 and minor in 5..8
    for s in seqs:
        for m in GENERIC_VERSION_RE.finditer(s):
            maj = int(m.group(1)); minv = int(m.group(2)); pat = int(m.group(3))
            if maj == 2 and minv in VULN_THRESHOLDS:
                return f"{maj}.{minv}.{pat}"
    return None


def parse_version_tuple(ver_str: str) -> Tuple[int, int, int]:
    parts = ver_str.split(".")
    parts = (parts + ["0", "0"])[:3]
    try:
        return int(parts[0]), int(parts[1]), int(parts[2])
    except Exception:
        return 0, 0, 0


def is_version_vulnerable(ver_str: Optional[str]) -> Optional[bool]:
    """
    判断给定版本字符串是否属于受影响范围
    返回 True / False / None (unknown)
    """
    if not ver_str:
        return None
    major, minor, patch = parse_version_tuple(ver_str)
    if major != 2 or minor not in VULN_THRESHOLDS:
        return False
    threshold = VULN_THRESHOLDS[minor]
    return patch < threshold


def check_device_paths(device: Optional[str], tmpdir: str) -> List[Dict]:
    results = []
    for p in DEVICE_PATHS:
        entry = {"device": device or "local", "path": p, "exists": False, "local_copy": None, "version": None, "vulnerable": None}
        if device_file_exists(device, p):
            entry["exists"] = True
            localname = os.path.basename(p)
            localpath = os.path.join(tmpdir, f"{(device or 'dev').replace(':','_')}_{localname}")
            ok = adb_pull_to(device, p, localpath)
            if ok:
                entry["local_copy"] = localpath
                ver = find_version_in_binary(localpath)
                entry["version"] = ver
                entry["vulnerable"] = is_version_vulnerable(ver)
                logging.warning(f"{device or 'device'}: pulled {p} -> {localpath}; version={ver}; vulnerable={entry['vulnerable']}")
            else:
                logging.warning(f"{device or 'device'}: {p} exists but pull failed")
        else:
            logging.warning(f"{device or 'device'}: {p} not present")
        results.append(entry)
    return results


def scan_local_apks_for_libs(cwd: str, tmpdir: str) -> List[Dict]:
    results: List[Dict] = []
    for fname in os.listdir(cwd):
        if not fname.lower().endswith(".apk"):
            continue
        apk_path = os.path.join(cwd, fname)
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for zi in zf.namelist():
                    # look for lib/**/libavformat.so
                    if zi.endswith("libavformat.so"):
                        # extract
                        local_name = f"{os.path.splitext(fname)[0]}_{os.path.basename(zi)}"
                        local_path = os.path.join(tmpdir, local_name)
                        try:
                            with zf.open(zi) as src, open(local_path, "wb") as dst:
                                shutil.copyfileobj(src, dst)
                            ver = find_version_in_binary(local_path)
                            vuln = is_version_vulnerable(ver)
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
            logging.warning(f"{apk_path} is not a valid APK/zip")
        except Exception as e:
            logging.warning(f"error opening {apk_path}: {e}")
    return results


def run_check():
    parser = argparse.ArgumentParser(description="检测 libavformat.so 是否为受 CVE-2016-1897 影响的旧版本")
    parser.add_argument("--serial", help="adb device serial (optional)")
    args = parser.parse_args()

    devices = [args.serial] if args.serial else list_adb_devices()

    tmpdir = tempfile.mkdtemp(prefix="cve2016_1897_")
    logging.warning(f"temporary files will be saved under {tmpdir}")

    overall_vulns = []

    # Check device paths for each device (if any)
    if devices:
        for dev in devices:
            logging.warning(f"checking device: {dev}")
            dev_results = check_device_paths(dev, tmpdir)
            for r in dev_results:
                if r.get("vulnerable") is True:
                    overall_vulns.append(("device", dev, r))
    else:
        logging.warning("no adb devices found or specified; skipping device checks")

    # Always scan local APKs
    logging.warning("scanning local APKs in current directory for libavformat.so ...")
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
        logging.warning("no vulnerable libavformat.so (matching CVE-2016-1897 vulnerable ranges) found in checked locations")
        return False
    else:
        logging.warning("VULNERABILITIES FOUND:")
        for kind, src, info in overall_vulns:
            if kind == "device":
                logging.warning(f"device {src}: path {info['path']} version={info['version']} extracted={info.get('local_copy')}")
            else:
                logging.warning(f"apk {src}: lib {info['lib_in_apk']} version={info['version']} extracted={info['extracted']}")
        return True



# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc21LibavformatExportPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测系统或app是否使用了不安全的libavformat.so库-v1（CVE-2016-1897）...'
    meta_cve_id = 'CVE-2016-1897'
    meta_severity = 'Critical'
    meta_protocol = 'http'
    meta_target_os = ['android']
    meta_required_params = ['target_ip']
    meta_profiles = ['advanced_network']
    meta_attack_surface = '第三方组件/高级漏洞'
    is_disruptive = False
    meta_destructive_level = 'Probe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

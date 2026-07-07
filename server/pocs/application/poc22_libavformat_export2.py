#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detect_cve_2016_1898.py

Detect if vulnerable libavformat.so versions affected by CVE-2016-1898 are used in systems or APKs
CVE-2016-1898 is同源 (homologous) to CVE-2016-1897, both are path traversal vulnerabilities in FFmpeg HLS protocol parsing
(CVE-2016-1898 allows reading arbitrary file lines, with the same impact scope and affected versions)

Affected version ranges (by minor branch):
 - 2.8.x where patch < 5
 - 2.7.x where patch < 5
 - 2.6.x where patch < 7
 - 2.5.x where patch < 10

Workflow:
1) Check predefined paths on connected devices (if any) and attempt to pull files for local analysis
2) Scan all APKs in the current directory to find lib/**/libavformat.so and extract for analysis
3) Support dual verification: version check + fixed feature string ("file,")
4) Output detection results and summary via logging.warning

Notes:
- This script only performs read-only detection and analysis; it will not modify target devices or APKs.
- Version extraction is based on printable strings in binaries, with certain uncertainty (marked as Unknown if version cannot be parsed).
- Supplementary feature string detection ("file,") improves detection accuracy (core marker of official fix patch).
"""
POC_TAG = "22. 检测系统或app是否使用了不安全的libavformat.so库-v2（CVE-2016-1898）..."

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
# Common paths of libavformat.so on Android devices (covers 32/64-bit systems)
DEVICE_PATHS = [
    "/system/lib/libavformat.so",
    "/system/lib64/libavformat.so",
    "/vendor/lib/libavformat.so",
    "/vendor/lib64/libavformat.so",
    "/system/app/*/lib/arm64-v8a/libavformat.so",
    "/system/app/*/lib/armeabi-v7a/libavformat.so"
]

# Vulnerability version thresholds: minimum safe patch version for each minor branch (vulnerable if below)
VULN_THRESHOLDS = {
    8: 5,  # 2.8.x  patch < 5 is vulnerable
    7: 5,  # 2.7.x  patch < 5 is vulnerable
    6: 7,  # 2.6.x  patch < 7 is vulnerable
    5: 10  # 2.5.x  patch < 10 is vulnerable
}

# Version regex: prioritize matching 2.[5-8].patch pattern (core version range involved in the vulnerability)
VERSION_REGEX = re.compile(r'\b2\.(5|6|7|8)\.(\d{1,4})\b')
# Generic version regex: fallback match (captures any x.y.z format)
GENERIC_VERSION_RE = re.compile(r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,4})\b')
# Fixed feature string: core marker of official fix patch (vulnerability fixed if present)
FIXED_FEATURE_STR = "file,"
# Vulnerability-related feature string: concat protocol (core keyword for vulnerability exploitation, present in unpatched versions)
VULN_FEATURE_STR = "concat:"
# Minimum length of printable strings in binaries (filters invalid strings)
MIN_PRINTABLE_SEQ_LEN = 4


def run_cmd(cmd: List[str], timeout: float = 15.0) -> Tuple[int, str]:
    """Execute system command and return exit code and output"""
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False
        )
        out = proc.stdout or proc.stderr or b""
        try:
            txt = out.decode("utf-8", errors="ignore")
        except Exception:
            txt = out.decode("latin-1", errors="ignore")
        return proc.returncode, txt.strip()
    except subprocess.TimeoutExpired:
        return -1, "command timeout"
    except FileNotFoundError as e:
        return -2, f"command not found: {e}"
    except Exception as e:
        return -3, f"command error: {str(e)}"


def list_adb_devices() -> List[str]:
    """Get list of connected ADB devices"""
    code, out = run_cmd([ADB_CMD, "devices"], timeout=4.0)
    devices = []
    if code < 0 or not out:
        return devices
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln or ln.lower().startswith("list of devices"):
            continue
        parts = ln.split()
        if len(parts) >= 2 and parts[1] == "device":  # Only keep online devices
            devices.append(parts[0])
    return devices


def device_file_exists(device: Optional[str], path: str) -> bool:
    """Check if file exists at specified path on device"""
    cmd = [ADB_CMD]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "ls", path]
    code, out = run_cmd(cmd, timeout=6.0)
    if code < 0:
        return False
    # Filter "file not found" prompts (compatible with Chinese/English systems)
    if "No such file" in out or "没有那个文件或目录" in out:
        return False
    return True


def adb_pull_to(device: Optional[str], remote: str, local: str) -> bool:
    """Pull file from device to local via ADB"""
    cmd = [ADB_CMD]
    if device:
        cmd += ["-s", device]
    cmd += ["pull", remote, local]
    code, out = run_cmd(cmd, timeout=30.0)
    # Verify pull result: local file exists and size > 0
    return code == 0 and os.path.exists(local) and os.path.getsize(local) > 0


def extract_ascii_sequences_from_file(path: str, min_len: int = MIN_PRINTABLE_SEQ_LEN) -> List[str]:
    """Extract printable ASCII string sequences from binary file"""
    seqs: List[str] = []
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        logging.warning(f"Failed to read file {path}: {e}")
        return seqs

    current = bytearray()
    for b in data:
        if 32 <= b <= 126:  # Printable ASCII character range
            current.append(b)
        else:
            if len(current) >= min_len:
                try:
                    seqs.append(current.decode("utf-8", errors="ignore"))
                except Exception:
                    seqs.append(current.decode("latin-1", errors="ignore"))
            current = bytearray()
    # Process printable strings at the end of the file
    if len(current) >= min_len:
        try:
            seqs.append(current.decode("utf-8", errors="ignore"))
        except Exception:
            seqs.append(current.decode("latin-1", errors="ignore"))
    return seqs


def find_version_in_binary(path: str) -> Optional[str]:
    """Find FFmpeg version string in binary file, prioritize matching 2.[5-8].patch pattern"""
    seqs = extract_ascii_sequences_from_file(path, min_len=MIN_PRINTABLE_SEQ_LEN)
    # Prioritize matching core version range (2.5-2.8.x)
    for s in seqs:
        match = VERSION_REGEX.search(s)
        if match:
            minor = int(match.group(1))
            patch = int(match.group(2))
            return f"2.{minor}.{patch}"
    # Fallback match: any x.y.z version, filter versions with major=2 and minor in vulnerability range
    for s in seqs:
        match = GENERIC_VERSION_RE.search(s)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3))
            if major == 2 and minor in VULN_THRESHOLDS:
                return f"{major}.{minor}.{patch}"
    return None


def check_feature_strings_in_binary(path: str) -> Tuple[bool, bool]:
    """Check if binary file contains vulnerability feature string and fixed feature string"""
    seqs = extract_ascii_sequences_from_file(path, min_len=MIN_PRINTABLE_SEQ_LEN)
    has_vuln_feature = any(VULN_FEATURE_STR in s for s in seqs)
    has_fixed_feature = any(FIXED_FEATURE_STR in s for s in seqs)
    return has_vuln_feature, has_fixed_feature


def parse_version_tuple(ver_str: str) -> Tuple[int, int, int]:
    """Parse version string into (major, minor, patch) tuple"""
    parts = ver_str.split(".")
    # Complement missing version segments (default to 0)
    parts = (parts + ["0", "0"])[:3]
    try:
        return int(parts[0]), int(parts[1]), int(parts[2])
    except Exception:
        return 0, 0, 0


def is_version_vulnerable(ver_str: Optional[str]) -> Optional[bool]:
    """Determine if version is in affected range based on version string"""
    if not ver_str:
        return None  # Version cannot be parsed
    major, minor, patch = parse_version_tuple(ver_str)
    # Only focus on 2.x series with minor in vulnerability range
    if major != 2 or minor not in VULN_THRESHOLDS:
        return False
    # Compare if patch version is below safe threshold
    return patch < VULN_THRESHOLDS[minor]


def check_device_paths(device: Optional[str], tmpdir: str) -> List[Dict]:
    """Scan libavformat.so on device and analyze vulnerability status"""
    results = []
    for remote_path in DEVICE_PATHS:
        entry = {
            "device": device or "unknown",
            "remote_path": remote_path,
            "exists": False,
            "local_copy": None,
            "version": None,
            "has_vuln_feature": False,
            "has_fixed_feature": False,
            "vulnerable": None
        }
        # Check if file exists on device
        if device_file_exists(device, remote_path):
            entry["exists"] = True
            # Generate local save path (avoid special characters in device serial)
            device_prefix = (device or "dev").replace(":", "_").replace(".", "_")
            local_filename = f"{device_prefix}_{os.path.basename(remote_path)}"
            local_path = os.path.join(tmpdir, local_filename)
            # Pull file to local
            if adb_pull_to(device, remote_path, local_path):
                entry["local_copy"] = local_path
                # Extract version and feature strings
                entry["version"] = find_version_in_binary(local_path)
                entry["has_vuln_feature"], entry["has_fixed_feature"] = check_feature_strings_in_binary(local_path)
                # Comprehensive vulnerability judgment: fixed feature takes priority (marked as fixed if present)
                if entry["has_fixed_feature"]:
                    entry["vulnerable"] = False
                else:
                    # Use version judgment if no fixed feature
                    entry["vulnerable"] = is_version_vulnerable(entry["version"])
                # Log detailed information
                logging.warning(
                    f"Device {device or 'local'}: Pulled {remote_path} -> {local_path}\n"
                    f"  Version: {entry['version']} | concat: {entry['has_vuln_feature']} | file,: {entry['has_fixed_feature']} | Vulnerable: {entry['vulnerable']}"
                )
            else:
                logging.warning(f"Device {device or 'local'}: {remote_path} exists but pull failed")
        else:
            logging.warning(f"Device {device or 'local'}: {remote_path} not present")
        results.append(entry)
    return results


def scan_local_apks_for_libs(cwd: str, tmpdir: str) -> List[Dict]:
    """Scan APK files in current directory, extract libavformat.so and analyze vulnerability status"""
    results: List[Dict] = []
    for fname in os.listdir(cwd):
        apk_path = os.path.join(cwd, fname)
        # Only process APK files
        if not fname.lower().endswith(".apk"):
            continue
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                # Traverse all files in APK to filter libavformat.so
                for zip_info in zf.namelist():
                    if zip_info.endswith("libavformat.so") and "lib/" in zip_info:
                        # Generate local extraction path
                        apk_name = os.path.splitext(fname)[0]
                        lib_rel_path = zip_info.replace("/", "_").replace("\\", "_")
                        local_path = os.path.join(tmpdir, f"{apk_name}_{lib_rel_path}")
                        # Extract libavformat.so from APK to local
                        try:
                            with zf.open(zip_info) as src, open(local_path, "wb") as dst:
                                shutil.copyfileobj(src, dst)
                            # Analyze version and feature strings
                            version = find_version_in_binary(local_path)
                            has_vuln_feature, has_fixed_feature = check_feature_strings_in_binary(local_path)
                            # Comprehensive vulnerability judgment
                            if has_fixed_feature:
                                vulnerable = False
                            else:
                                vulnerable = is_version_vulnerable(version)
                            # Log detailed information
                            logging.warning(
                                f"APK {fname}: Found {zip_info} -> Extracted to {local_path}\n"
                                f"  Version: {version} | concat: {has_vuln_feature} | file,: {has_fixed_feature} | Vulnerable: {vulnerable}"
                            )
                            # Save result
                            results.append({
                                "apk_path": apk_path,
                                "lib_zip_path": zip_info,
                                "extracted_path": local_path,
                                "version": version,
                                "has_vuln_feature": has_vuln_feature,
                                "has_fixed_feature": has_fixed_feature,
                                "vulnerable": vulnerable
                            })
                        except Exception as e:
                            logging.warning(f"APK {fname}: Failed to extract {zip_info}: {str(e)}")
        except zipfile.BadZipFile:
            logging.warning(f"{apk_path} is not a valid APK/zip file")
        except Exception as e:
            logging.warning(f"Error processing {apk_path}: {str(e)}")
    return results


def main():
    parser = argparse.ArgumentParser(description="Detect if libavformat.so is affected by CVE-2016-1898 vulnerability")
    parser.add_argument("--serial",
                        help="Specify ADB device serial (optional; auto-detect all online devices if not specified)")
    args = parser.parse_args()

    # Get target device list
    devices = [args.serial] if args.serial else list_adb_devices()
    # Create temporary directory to store pulled/extracted files
    tmpdir = tempfile.mkdtemp(prefix="cve2016_1898_")
    logging.warning(f"Temporary file directory: {tmpdir} (automatically deleted after script execution)")

    # Store all vulnerability results
    overall_vulns = []

    # 1. Scan libavformat.so on devices
    if devices:
        for dev in devices:
            logging.warning(f"\n===== Start scanning device: {dev} =====")
            dev_results = check_device_paths(dev, tmpdir)
            for res in dev_results:
                if res["vulnerable"] is True:
                    overall_vulns.append(("device", dev, res))
    else:
        logging.warning("\n===== No online ADB devices detected, skipping device scan =====")

    # 2. Scan APK files in current directory
    logging.warning("\n===== Start scanning APK files in current directory =====")
    apk_results = scan_local_apks_for_libs(os.getcwd(), tmpdir)
    for res in apk_results:
        if res["vulnerable"] is True:
            overall_vulns.append(("apk", res["apk_path"], res))

    # Clean up temporary directory
    if os.path.exists(tmpdir):
        try:
            shutil.rmtree(tmpdir)
            logging.warning(f"\nTemporary directory {tmpdir} deleted successfully")
        except Exception as e:
            logging.warning(f"\nFailed to delete temporary directory {tmpdir}: {str(e)}")

    # Output vulnerability summary
    logging.warning("\n" + "=" * 50)
    if not overall_vulns:
        logging.warning("[Result] No libavformat.so versions affected by CVE-2016-1898 found in checked locations")
        return False
    else:
        logging.warning(f"[Result] Found {len(overall_vulns)} targets affected by the vulnerability:")
        return True



if __name__ == "__main__":
    main()









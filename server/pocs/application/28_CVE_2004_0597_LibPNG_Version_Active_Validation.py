#!/usr/bin/env python3
"""
PoC Name  : 检测系统或app是否使用了不安全的libpng.so库（CVE-2004-0597）...
CVE       : CVE-2004-0597
Category  : application
Severity  : High
Type      : Type-A
Description: 检测系统或app是否使用了不安全的libpng.so库（CVE-2004-0597）... vulnerability detection.
Prerequisites: See HW_REQUIREMENTS or VULN dict for details.
Usage     : python3 28_CVE_2004_0597_LibPNG_Version_Active_Validation.py <target_ip>
"""

from __future__ import annotations
POC_TAG = "23. 检测系统或app是否使用了不安全的libpng.so库（CVE-2004-0597）..."


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
# Common libpng paths on Android/Linux/macOS (covers 32/64-bit systems)
DEVICE_PATHS = [
    # Android paths
    "/system/lib/libpng.so",
    "/system/lib64/libpng.so",
    "/vendor/lib/libpng.so",
    "/vendor/lib64/libpng.so",
    "/system/app/*/lib/arm64-v8a/libpng.so",
    "/system/app/*/lib/armeabi-v7a/libpng.so",
    "/system/lib/libpng16.so",  # Common variant naming
    "/system/lib64/libpng16.so",
    # Linux/macOS paths (for device-side detection)
    "/usr/lib/libpng.so",
    "/usr/lib64/libpng.so",
    "/usr/local/lib/libpng.so",
    "/usr/lib/libpng.dylib",
    "/usr/local/lib/libpng.dylib"
]

# Version regex: Match libpng version patterns (e.g., 1.2.4, 1.0.15, libpng-1.2.3)
PNG_VERSION_REGEX = re.compile(
    r'(libpng-)?(\d+\.\d+\.\d+)'  # Capture version like "1.2.4" or "libpng-1.0.10"
    r'|'
    r'PNG_LIBPNG_VER_STRING\s*"(\d+\.\d+\.\d+)"',  # Capture version from define string
    re.IGNORECASE
)

# Minimum safe version for CVE-2004-0597 (versions below are vulnerable)
SAFE_VERSION = (1, 2, 5)
# Minimum length of printable strings for valid extraction
MIN_PRINTABLE_SEQ_LEN = 3


def run_cmd(cmd: List[str], timeout: float = 15.0) -> Tuple[int, str]:
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
    cmd = [ADB_CMD]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "ls", path]
    code, out = run_cmd(cmd, timeout=6.0)
    if code < 0:
        return False
    # Filter "file not found" prompts (compatible with multi-language systems)
    if "No such file" in out or "没有那个文件或目录" in out or "datei nicht gefunden" in out:
        return False
    return True


def adb_pull_to(device: Optional[str], remote: str, local: str) -> bool:
    cmd = [ADB_CMD]
    if device:
        cmd += ["-s", device]
    cmd += ["pull", remote, local]
    code, out = run_cmd(cmd, timeout=30.0)
    # Verify pull result: local file exists and size > 0
    return code == 0 and os.path.exists(local) and os.path.getsize(local) > 0


def extract_ascii_sequences_from_file(path: str, min_len: int = MIN_PRINTABLE_SEQ_LEN) -> List[str]:
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


def find_libpng_version(path: str) -> Optional[str]:
    seqs = extract_ascii_sequences_from_file(path)
    for s in seqs:
        match = PNG_VERSION_REGEX.search(s)
        if match:
            # Extract version from any matching group
            version = match.group(2) or match.group(3)
            if version:
                return version.strip()
    return None


def parse_version_tuple(ver_str: str) -> Tuple[int, int, int]:
    parts = ver_str.split(".")
    # Complement missing version segments (default to 0)
    parts = (parts + ["0", "0"])[:3]
    try:
        return (
            int(parts[0]) if parts[0].isdigit() else 0,
            int(parts[1]) if parts[1].isdigit() else 0,
            int(parts[2]) if parts[2].isdigit() else 0
        )
    except Exception:
        return 0, 0, 0


def is_libpng_vulnerable(ver_str: Optional[str]) -> Optional[bool]:
    if not ver_str:
        return None  # Version unparseable

    ver_tuple = parse_version_tuple(ver_str)
    # Vulnerable if version < 1.2.5
    if ver_tuple < SAFE_VERSION:
        return True
    # Safe if version >= 1.2.5
    return False


def is_libpng_binary(path: str) -> bool:
    seqs = extract_ascii_sequences_from_file(path)
    # libpng signature strings (case-insensitive)
    png_signatures = ["libpng", "PNG image", "PNG_LIBPNG_VER", "png_", "PNG_"]
    return any(signature.lower() in s.lower() for s in seqs for signature in png_signatures)


def check_device_paths(device: Optional[str], tmpdir: str) -> List[Dict]:
    results = []
    for remote_path in DEVICE_PATHS:
        entry = {
            "device": device or "unknown",
            "remote_path": remote_path,
            "exists": False,
            "is_libpng": False,
            "local_copy": None,
            "version": None,
            "vulnerable": None
        }

        if device_file_exists(device, remote_path):
            entry["exists"] = True
            # Generate safe local filename
            device_prefix = (device or "dev").replace(":", "_").replace(".", "_")
            local_filename = f"{device_prefix}_{os.path.basename(remote_path)}"
            local_path = os.path.join(tmpdir, local_filename)

            if adb_pull_to(device, remote_path, local_path):
                entry["local_copy"] = local_path
                # Verify if it's a valid libpng binary
                entry["is_libpng"] = is_libpng_binary(local_path)

                if entry["is_libpng"]:
                    entry["version"] = find_libpng_version(local_path)
                    entry["vulnerable"] = is_libpng_vulnerable(entry["version"])
                    logging.warning(
                        f"Device {device or 'local'}: Valid libpng found at {remote_path} -> Extracted to {local_path}\n"
                        f"  Version: {entry['version']} | Vulnerable to CVE-2004-0597: {entry['vulnerable']}"
                    )
                else:
                    logging.warning(
                        f"Device {device or 'local'}: File exists at {remote_path} but is not libpng -> {local_path}"
                    )
            else:
                logging.warning(f"Device {device or 'local'}: {remote_path} exists but pull failed")
        else:
            logging.debug(f"Device {device or 'local'}: {remote_path} not present (debug)")

        results.append(entry)
    return results


def scan_local_apks_for_libs(cwd: str, tmpdir: str) -> List[Dict]:
    results: List[Dict] = []
    for fname in os.listdir(cwd):
        apk_path = os.path.join(cwd, fname)
        if not fname.lower().endswith(".apk"):
            continue

        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for zip_info in zf.namelist():
                    # Filter libpng-related .so files (including variants)
                    if zip_info.endswith(".so") and ("libpng" in zip_info.lower() or "png" in zip_info.lower()):
                        # Generate local extraction path
                        apk_name = os.path.splitext(fname)[0]
                        safe_zip_path = zip_info.replace("/", "_").replace("\\", "_").replace(":", "_")
                        local_path = os.path.join(tmpdir, f"{apk_name}_{safe_zip_path}")

                        try:
                            # Extract .so file from APK
                            with zf.open(zip_info) as src, open(local_path, "wb") as dst:
                                shutil.copyfileobj(src, dst)

                            # Verify if it's a valid libpng binary
                            if is_libpng_binary(local_path):
                                version = find_libpng_version(local_path)
                                vulnerable = is_libpng_vulnerable(version)

                                logging.warning(
                                    f"APK {fname}: Valid libpng found at {zip_info} -> Extracted to {local_path}\n"
                                    f"  Version: {version} | Vulnerable to CVE-2004-0597: {vulnerable}"
                                )

                                results.append({
                                    "apk_path": apk_path,
                                    "lib_zip_path": zip_info,
                                    "extracted_path": local_path,
                                    "version": version,
                                    "vulnerable": vulnerable
                                })
                            else:
                                logging.debug(f"APK {fname}: File {zip_info} is not libpng (debug)")

                        except Exception as e:
                            logging.warning(f"APK {fname}: Failed to extract {zip_info}: {str(e)}")
        except zipfile.BadZipFile:
            logging.warning(f"{apk_path} is not a valid APK/zip file")
        except Exception as e:
            logging.warning(f"Error processing {apk_path}: {str(e)}")

    return results


def run_check():
    parser = argparse.ArgumentParser(
        description="Detect CVE-2004-0597 (libpng integer overflow vulnerability) on devices/APKs")
    parser.add_argument("--serial", help="Specify ADB device serial (optional; auto-detect online devices if omitted)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging for detailed scanning process")
    args = parser.parse_args()

    # Adjust logging level if debug mode is enabled
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Get target devices
    devices = [args.serial] if args.serial else list_adb_devices()
    # Create temporary directory for pulled/extracted files
    tmpdir = tempfile.mkdtemp(prefix="cve2004_0597_")
    logging.warning(f"Temporary directory: {tmpdir} (auto-deleted after execution)")

    overall_vulns = []

    # 1. Scan devices for libpng
    if devices:
        for dev in devices:
            logging.warning(f"\n===== Starting device scan: {dev} =====")
            dev_results = check_device_paths(dev, tmpdir)
            for res in dev_results:
                if res["is_libpng"] and res["vulnerable"] is True:
                    overall_vulns.append(("device", dev, res))
    else:
        logging.warning("\n===== No online ADB devices detected; skipping device scan =====")

    # 2. Scan local APKs for embedded libpng
    logging.warning("\n===== Starting local APK scan (current directory) =====")
    apk_results = scan_local_apks_for_libs(os.getcwd(), tmpdir)
    for res in apk_results:
        if res["vulnerable"] is True:
            overall_vulns.append(("apk", res["apk_path"], res))

    # Clean up temporary directory
    if os.path.exists(tmpdir):
        try:
            shutil.rmtree(tmpdir)
            logging.warning(f"\nTemporary directory {tmpdir} cleaned up successfully")
        except Exception as e:
            logging.warning(f"\nFailed to clean up temporary directory {tmpdir}: {str(e)}")

    # Output final summary
    logging.warning("\n" + "=" * 60)
    if not overall_vulns:
        logging.warning("[Result] No libpng versions vulnerable to CVE-2004-0597 found in scanned targets")
        logging.warning(f"Note: Only libpng versions < {'.'.join(map(str, SAFE_VERSION))} are vulnerable")
        return False
    else:
        logging.warning(f"[Result] Found {len(overall_vulns)} vulnerable target(s) for CVE-2004-0597:")
        return True



# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc23LibpngExportPlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-APP-028"
    meta_poc_name = 'CVE-2004-0597 LibPNG Version Active Validation'
    meta_cve_id = 'CVE-2004-0597'
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2004-0597'
    meta_references = ['https://nvd.nist.gov/vuln/detail/CVE-2004-0597']
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

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "28_LibPNG_Version_Audit") if "VULN" in dir() else "28_LibPNG_Version_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc23LibpngExportPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

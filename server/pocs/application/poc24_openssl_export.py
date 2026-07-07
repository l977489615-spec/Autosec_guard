#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detect_cve_2016_6309.py

Detect if systems or Android devices are affected by CVE-2016-6309 (OpenSSL DOS vulnerability)
CVE-2016-6309: Integer overflow in OpenSSL 1.1.0a, leading to heap-based buffer overflow
Affected version: OpenSSL 1.1.0a (EXCLUSIVELY) - Fixed in OpenSSL 1.1.0b and later
Vulnerability impact: Remote denial of service (DOS) via specially crafted DTLS packets
                     (Attacker can crash OpenSSL-dependent applications/services)

Workflow:
1) Check predefined paths for OpenSSL libraries (libssl.so/libcrypto.so) on Android/Linux via ADB
2) Scan local APK files for embedded OpenSSL libraries
3) Extract OpenSSL version from binaries and verify against vulnerable version (1.1.0a)
4) Output detection results and summary in English

Notes:
- Read-only detection: No modification to target devices or APKs
- Version extraction relies on printable strings in binaries (marked as Unknown if unparseable)
- Only OpenSSL 1.1.0a is vulnerable; earlier (1.0.x) or later (1.1.0b+) versions are safe
"""
POC_TAG = "24. 检测系统或app是否使用了不安全的openssl（CVE-2016_6309）..."

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
# Common OpenSSL library paths on Android/Linux (covers 32/64-bit systems)
# Target libraries: libssl.so (core SSL/TLS) and libcrypto.so (crypto core, linked with OpenSSL)
DEVICE_PATHS = [
    # Android system/vendor paths
    "/system/lib/libssl.so",
    "/system/lib64/libssl.so",
    "/vendor/lib/libssl.so",
    "/vendor/lib64/libssl.so",
    "/system/lib/libcrypto.so",
    "/system/lib64/libcrypto.so",
    "/vendor/lib/libcrypto.so",
    "/vendor/lib64/libcrypto.so",
    # Android app-specific paths
    "/system/app/*/lib/arm64-v8a/libssl.so",
    "/system/app/*/lib/armeabi-v7a/libssl.so",
    "/system/app/*/lib/arm64-v8a/libcrypto.so",
    "/system/app/*/lib/armeabi-v7a/libcrypto.so",
    # Linux system paths (for device-side detection)
    "/usr/lib/libssl.so",
    "/usr/lib64/libssl.so",
    "/usr/local/lib/libssl.so",
    "/usr/lib/libcrypto.so",
    "/usr/lib64/libcrypto.so",
    "/usr/local/lib/libcrypto.so",
    # Versioned variants (common in embedded systems)
    "/system/lib/libssl.so.1.1",
    "/system/lib64/libssl.so.1.1",
    "/vendor/lib/libcrypto.so.1.1",
    "/vendor/lib64/libcrypto.so.1.1"
]

# Version regex: Match OpenSSL version patterns (e.g., 1.1.0a, OpenSSL 1.1.0a, libssl-1.1.0a)
OPENSSL_VERSION_REGEX = re.compile(
    r'(OpenSSL |libssl-|SSLv3_|OPENSSL_)(\d+\.\d+\.\d+[a-z]?)',
    re.IGNORECASE
)

# Vulnerable version for CVE-2016-6309 (EXCLUSIVE)
VULNERABLE_VERSION = "1.1.0a"
# Minimum length of printable strings for valid extraction
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
    # Filter "file not found" prompts (compatible with multi-language systems)
    if "No such file" in out or "没有那个文件或目录" in out or "datei nicht gefunden" in out:
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


def find_openssl_version(path: str) -> Optional[str]:
    """Find OpenSSL version string in binary file (libssl.so/libcrypto.so)"""
    seqs = extract_ascii_sequences_from_file(path)
    for s in seqs:
        match = OPENSSL_VERSION_REGEX.search(s)
        if match:
            version = match.group(2).strip()
            # Validate version format (e.g., 1.1.0a, 1.0.2k)
            if re.match(r'\d+\.\d+\.\d+[a-z]?', version, re.IGNORECASE):
                return version.lower()  # Normalize to lowercase (e.g., 1.1.0A → 1.1.0a)
    return None


def is_openssl_binary(path: str) -> bool:
    """Check if binary file is OpenSSL-related (libssl.so/libcrypto.so)"""
    seqs = extract_ascii_sequences_from_file(path)
    # OpenSSL signature strings (case-insensitive)
    openssl_signatures = [
        "OpenSSL", "libssl", "libcrypto", "SSL_", "TLS_",
        "EVP_", "AES_", "RSA_", "SHA_"
    ]
    return any(signature.lower() in s.lower() for s in seqs for signature in openssl_signatures)


def is_openssl_vulnerable(ver_str: Optional[str]) -> Optional[bool]:
    """Determine if OpenSSL version is vulnerable to CVE-2016-6309"""
    if not ver_str:
        return None  # Version unparseable

    # CVE-2016-6309 ONLY affects OpenSSL 1.1.0a
    return ver_str == VULNERABLE_VERSION.lower()


def check_device_paths(device: Optional[str], tmpdir: str) -> List[Dict]:
    """Scan OpenSSL libraries on device and analyze vulnerability status"""
    results = []
    for remote_path in DEVICE_PATHS:
        entry = {
            "device": device or "unknown",
            "remote_path": remote_path,
            "exists": False,
            "is_openssl": False,
            "local_copy": None,
            "version": None,
            "vulnerable": None
        }

        if device_file_exists(device, remote_path):
            entry["exists"] = True
            # Generate safe local filename (avoid special characters)
            device_prefix = (device or "dev").replace(":", "_").replace(".", "_")
            lib_basename = os.path.basename(remote_path)
            local_filename = f"{device_prefix}_{lib_basename}"
            local_path = os.path.join(tmpdir, local_filename)

            if adb_pull_to(device, remote_path, local_path):
                entry["local_copy"] = local_path
                # Verify if it's a valid OpenSSL binary
                entry["is_openssl"] = is_openssl_binary(local_path)

                if entry["is_openssl"]:
                    entry["version"] = find_openssl_version(local_path)
                    entry["vulnerable"] = is_openssl_vulnerable(entry["version"])
                    logging.warning(
                        f"Device {device or 'local'}: Valid OpenSSL library found at {remote_path} -> Extracted to {local_path}\n"
                        f"  Version: {entry['version']} | Vulnerable to CVE-2016-6309: {entry['vulnerable']}"
                    )
                else:
                    logging.debug(
                        f"Device {device or 'local'}: File exists at {remote_path} but is not OpenSSL-related -> {local_path}"
                    )
            else:
                logging.warning(f"Device {device or 'local'}: {remote_path} exists but pull failed")
        else:
            logging.debug(f"Device {device or 'local'}: {remote_path} not present (debug)")

        results.append(entry)
    return results


def scan_local_apks_for_libs(cwd: str, tmpdir: str) -> List[Dict]:
    """Scan local APKs for embedded OpenSSL libraries and analyze vulnerability"""
    results: List[Dict] = []
    for fname in os.listdir(cwd):
        apk_path = os.path.join(cwd, fname)
        if not fname.lower().endswith(".apk"):
            continue

        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for zip_info in zf.namelist():
                    # Filter OpenSSL-related .so files (libssl.so/libcrypto.so and variants)
                    if zip_info.endswith(".so") and ("libssl" in zip_info.lower() or "libcrypto" in zip_info.lower()):
                        # Generate safe local extraction path
                        apk_name = os.path.splitext(fname)[0]
                        safe_zip_path = zip_info.replace("/", "_").replace("\\", "_").replace(":", "_")
                        local_path = os.path.join(tmpdir, f"{apk_name}_{safe_zip_path}")

                        try:
                            # Extract .so file from APK
                            with zf.open(zip_info) as src, open(local_path, "wb") as dst:
                                shutil.copyfileobj(src, dst)

                            # Verify if it's a valid OpenSSL binary
                            if is_openssl_binary(local_path):
                                version = find_openssl_version(local_path)
                                vulnerable = is_openssl_vulnerable(version)

                                logging.warning(
                                    f"APK {fname}: Valid OpenSSL library found at {zip_info} -> Extracted to {local_path}\n"
                                    f"  Version: {version} | Vulnerable to CVE-2016-6309: {vulnerable}"
                                )

                                results.append({
                                    "apk_path": apk_path,
                                    "lib_zip_path": zip_info,
                                    "extracted_path": local_path,
                                    "version": version,
                                    "vulnerable": vulnerable
                                })
                            else:
                                logging.debug(f"APK {fname}: File {zip_info} is not OpenSSL-related (debug)")

                        except Exception as e:
                            logging.warning(f"APK {fname}: Failed to extract {zip_info}: {str(e)}")
        except zipfile.BadZipFile:
            logging.warning(f"{apk_path} is not a valid APK/zip file")
        except Exception as e:
            logging.warning(f"Error processing {apk_path}: {str(e)}")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Detect CVE-2016-6309 (OpenSSL 1.1.0a DOS vulnerability) on devices/APKs")
    parser.add_argument("--serial", help="Specify ADB device serial (optional; auto-detect online devices if omitted)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging for detailed scanning process")
    args = parser.parse_args()

    # Adjust logging level if debug mode is enabled
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Get target devices
    devices = [args.serial] if args.serial else list_adb_devices()
    # Create temporary directory for pulled/extracted files
    tmpdir = tempfile.mkdtemp(prefix="cve2016_6309_")
    logging.warning(f"Temporary directory: {tmpdir} (auto-deleted after execution)")

    overall_vulns = []

    # 1. Scan devices for OpenSSL libraries
    if devices:
        for dev in devices:
            logging.warning(f"\n===== Starting device scan: {dev} =====")
            dev_results = check_device_paths(dev, tmpdir)
            for res in dev_results:
                if res["is_openssl"] and res["vulnerable"] is True:
                    overall_vulns.append(("device", dev, res))
    else:
        logging.warning("\n===== No online ADB devices detected; skipping device scan =====")

    # 2. Scan local APKs for embedded OpenSSL libraries
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
        logging.warning("[Result] No OpenSSL versions vulnerable to CVE-2016-6309 found in scanned targets")
        logging.warning(f"Note: Only OpenSSL {VULNERABLE_VERSION} is vulnerable (fixed in 1.1.0b+)")
        return False
    else:
        logging.warning(f"[Result] Found {len(overall_vulns)} vulnerable target(s) for CVE-2016-6309:")
        for kind, src, res in overall_vulns:
            if kind == "device":
                logging.warning(
                    f"- Device: {src} | Path: {res['remote_path']} | Version: {res['version']} | Local copy: {res['local_copy']}")
            else:
                logging.warning(
                    f"- APK: {src} | Lib path: {res['lib_zip_path']} | Version: {res['version']} | Extracted path: {res['extracted_path']}")
        logging.warning(
            f"\nRecommendation: Upgrade OpenSSL from {VULNERABLE_VERSION} to 1.1.0b or later to fix the DOS vulnerability")
        return True


if __name__ == "__main__":
    main()
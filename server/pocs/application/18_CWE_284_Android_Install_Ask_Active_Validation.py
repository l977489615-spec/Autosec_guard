#!/usr/bin/env python3
"""
PoC Name  : 检测设备是否允许未经警告的第三方app安装...
CVE       : CWE-284
Category  : application
Severity  : Medium
Type      : Type-A
Description: 检测设备是否允许未经警告的第三方app安装... vulnerability detection.
Prerequisites: See HW_REQUIREMENTS or VULN dict for details.
Usage     : python3 18_CWE_284_Android_Install_Ask_Active_Validation.py <target_ip>
"""

from __future__ import annotations
POC_TAG = "13. 检测设备是否允许未经警告的第三方app安装..."


from typing import Tuple, Optional, List
import subprocess
import logging
import argparse
import os
import time
import sys
import shlex

# logging 配置
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

ADB_CMD = "adb"
APK_LOCAL_NAME = "via-release-cn.apk"
REMOTE_PATH = "/sdcard/" + APK_LOCAL_NAME
CHECK_COMPONENT = "com.android.packageinstaller"
DUMPSYS_GREP_MARK = "mResumedActivity"
PUSH_TIMEOUT = 30.0
CMD_TIMEOUT = 8.0
SLEEP_AFTER_START = 1.5  # wait for activity to appear


def run_cmd(cmd: List[str], timeout: float = CMD_TIMEOUT) -> Tuple[int, str]:
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        out = proc.stdout or proc.stderr or b""
        try:
            txt = out.decode("utf-8", errors="ignore")
        except Exception:
            txt = out.decode("gbk", errors="ignore")
        return proc.returncode, txt.strip()
    except subprocess.TimeoutExpired:
        return -1, ""
    except FileNotFoundError as e:
        return -2, str(e)
    except Exception as e:
        return -3, str(e)


def adb_prefix(serial: Optional[str]) -> List[str]:
    return [ADB_CMD, "-s", serial] if serial else [ADB_CMD]


def adb_push(serial: Optional[str], local: str, remote: str) -> Tuple[bool, str]:
    cmd = adb_prefix(serial) + ["push", local, remote]
    code, out = run_cmd(cmd, timeout=PUSH_TIMEOUT)
    return code == 0, out


def adb_shell(serial: Optional[str], shell_cmd: str, timeout: float = CMD_TIMEOUT) -> Tuple[int, str]:
    cmd = adb_prefix(serial) + ["shell", shell_cmd]
    return run_cmd(cmd, timeout=timeout)


def adb_devices(serial: Optional[str] = None) -> List[str]:
    code, out = run_cmd([ADB_CMD, "devices"], timeout=3.0)
    if code != 0 or not out:
        return []
    devices = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln or ln.lower().startswith("list of devices"):
            continue
        parts = ln.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    if serial:
        return [d for d in devices if d == serial]
    return devices


def start_install_intent(serial: Optional[str]) -> Tuple[bool, str]:
    # Build shell command string carefully, use shlex.quote where appropriate
    # Many devices accept a plain am start command without extra quoting, but we quote URI
    intent = (
        "am start -n com.android.packageinstaller/.InstallStart "
        "-a android.intent.action.VIEW "
        "-d file:///sdcard/{} -t application/vnd.android.package-archive"
    ).format(shlex.quote(APK_LOCAL_NAME))
    # Use single shell invocation
    code, out = adb_shell(serial, intent, timeout=CMD_TIMEOUT)
    return (code == 0), out


def get_top_activity_line(serial: Optional[str]) -> Optional[str]:
    # Use dumpsys activity activities
    cmd = "dumpsys activity activities"
    code, out = adb_shell(serial, cmd, timeout=6.0)
    if code < 0 or not out:
        return None
    # Search for a line that contains DUMPSYS_GREP_MARK
    for ln in out.splitlines():
        if DUMPSYS_GREP_MARK in ln:
            return ln.strip()
    return None


def press_home(serial: Optional[str]) -> None:
    # KEYCODE_HOME is 3
    adb_shell(serial, "input keyevent 4", timeout=2.0)


def run_check():
    parser = argparse.ArgumentParser(description="push apk, start installer intent and check top activity")
    parser.add_argument("--serial", help="adb device serial (optional)")
    parser.add_argument("--no-push", action="store_true", help="if set, do not push even if local apk exists")
    args = parser.parse_args()
    serial = args.serial

    # ensure device present if serial provided or any device
    devices = adb_devices(serial)
    if not devices:
        logging.warning("no adb devices found or specified device not online")
        sys.exit(0)

    target_device = devices[0] if not serial else serial
    logging.warning(f"target device: {target_device}")

    cwd = os.getcwd()
    local_apk_path = os.path.join(cwd, APK_LOCAL_NAME)
    if os.path.isfile(local_apk_path) and os.path.getsize(local_apk_path) > 0:
        logging.warning(f"local apk found: {local_apk_path}")
        if args.no_push:
            logging.warning("no-push flag set; skipping push")
        else:
            ok, out = adb_push(target_device, local_apk_path, REMOTE_PATH)
            if not ok:
                logging.warning(f"adb push failed: {out}")
                # still proceed to intent start even if push failed (file may already exist on device)
            else:
                logging.warning("adb push succeeded")
    else:
        # local file not present -> fail early
        logging.warning(f"local apk {APK_LOCAL_NAME} not found in current directory")
        logging.warning("aborting because apk to push is missing")
        sys.exit(0)

    # start installer intent
    ok_start, out_start = start_install_intent(target_device)
    if ok_start:
        logging.warning("started install intent (am start returned success)")
    else:
        logging.warning(f"am start returned non-zero or no output: {out_start}")

    # small delay to allow activity to come to foreground
    time.sleep(SLEEP_AFTER_START)

    # get top activity
    top_line = get_top_activity_line(target_device)
    if top_line is None:
        logging.warning("could not obtain mResumedActivity line from dumpsys; treating as inconclusive")
        # still press home to cleanup
        press_home(target_device)
        sys.exit(0)

    logging.warning(f"dumpsys mResumedActivity line: {top_line}")

    # Decide vulnerability: if top activity contains CHECK_COMPONENT then no vuln
    # else vuln
    if CHECK_COMPONENT in top_line:
        logging.warning("TOP ACTIVITY is com.android.packageinstaller -> no vulnerability")
        return False
    else:
        logging.warning("TOP ACTIVITY is NOT com.android.packageinstaller -> VULNERABLE")
        return True

    # finally press home
    press_home(target_device)
    logging.warning("pressed HOME key to return to launcher")



# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable



import sys as _sys_adb
from pathlib import Path as _Path_adb
_sys_adb.path.insert(0, str(_Path_adb(__file__).parent))
try:
    from probe_utils import ADBProbe, detection_confidence
    _PROBE_UTILS_AVAILABLE = True
except ImportError:
    ADBProbe = None  # type: ignore
    detection_confidence = None  # type: ignore
    _PROBE_UTILS_AVAILABLE = False

try:
    from active_validation_core import run_active_validation as _run_active_validation
    _ACTIVE_VALIDATION_AVAILABLE = True
except ImportError:
    _run_active_validation = None  # type: ignore
    _ACTIVE_VALIDATION_AVAILABLE = False

VULN = {
    'cve': 'CWE-284',
    'year': 284,
    'source_url': 'https://cwe.mitre.org/data/definitions/284.html',
    'affected': [{'vendor': 'Unknown', 'product': 'Unknown', 'versions': []}],
    "id": 'CWE-284',
    "domain": "application",
    "vendor_product": "Android IVI Application",
    "component": 'install_unknown_sources',
    "type": 'configuration',
    "summary": '第三方 APK 安装权限检测',
    "requires_manual_review": True,
}


def _run_poc(plugin, vuln=None) -> dict:
    params = plugin.params or {}
    bt_serial = (
        params.get("adb_serial")
        or params.get("android_serial")
        or params.get("expected_usb_serial")
    )
    package = params.get("package") or params.get("android_package") or ""

    evidence: dict = {
        "check_type": 'android_install_unknown_sources',
        "technique": "ADB device interrogation + static analysis fallback",
    }

    if _PROBE_UTILS_AVAILABLE and ADBProbe is not None:
        try:
            adb = ADBProbe(serial=bt_serial)
            if adb.available():
                devices = adb.devices()
                evidence["adb_devices"] = [d["serial"] for d in devices]
                if devices:
                    if not bt_serial:
                        adb.serial = devices[0]["serial"]
                    device_info = adb.device_info()
                    evidence.update(device_info)
                    evidence["adb_connected"] = True
                    # ADB: check if unknown sources installation is allowed
                    install_setting = adb.shell(
                        "settings get global install_non_market_apps 2>/dev/null || "
                        "settings get secure install_non_market_apps 2>/dev/null"
                    )
                    install_setting2 = adb.shell(
                        "settings get global package_verifier_enable 2>/dev/null"
                    )
                    evidence["install_non_market_apps"] = install_setting.strip()
                    evidence["package_verifier_enable"] = install_setting2.strip()
                    vulnerable = install_setting.strip() == "1"
                    conf = detection_confidence("C", evidence, "adb_device_probe") if detection_confidence else {"level": "C"}
                    return {
                        "vulnerable": vulnerable,
                        "evidence": evidence,
                        "detection_confidence": conf,
                        "requires_manual_review": vulnerable is None,
                    }
        except Exception as _exc:
            evidence["adb_probe_error"] = str(_exc)

    evidence["adb_connected"] = False
    try:
        static_result = run_check()
    except SystemExit:
        static_result = None
    except Exception as _e:
        static_result = None
        evidence["static_analysis_error"] = str(_e)

    evidence["static_analysis_result"] = static_result
    conf = detection_confidence("D", evidence, "static_manifest_analysis") if detection_confidence else {"level": "D"}
    return {
        "vulnerable": static_result,
        "evidence": evidence,
        "detection_confidence": conf,
        "requires_manual_review": True,
    }

class Poc13InstallaskPlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-APP-018"
    meta_poc_name = 'CWE-284 Android Install Ask Active Validation'
    meta_cve_id = 'CWE-284'
    meta_source_url = 'https://cwe.mitre.org/data/definitions/284.html'
    meta_references = ['https://cwe.mitre.org/data/definitions/284.html']
    meta_severity = 'Medium'
    meta_protocol = 'android'
    meta_target_os = ['android']
    meta_required_params = ['expected_usb_serial']
    meta_profiles = ['usb_adb']
    meta_attack_surface = '固件/USB/OTA'
    is_disruptive = True
    meta_destructive_level = 'Disruptive'

    def check_prerequisites(self):
        return True

    def exploit(self):
        if _ACTIVE_VALIDATION_AVAILABLE and _run_active_validation is not None:
            return _run_active_validation(self, VULN, probe=_run_poc)
        return execute_check_callable(run_check, self)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "18_Android_Install_Ask_Audit") if "VULN" in dir() else "18_Android_Install_Ask_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc13InstallaskPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

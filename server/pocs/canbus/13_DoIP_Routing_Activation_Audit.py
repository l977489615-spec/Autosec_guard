#!/usr/bin/env python3
"""Safe DoIP routing activation pre-check without diagnostic payloads."""
from __future__ import annotations

import os
import socket

POC_TAG = "135. DoIP Routing Activation 前置条件检测"


def run_check() -> bool:
    host = os.environ.get("AUTOSEC_TARGET_IP") or os.environ.get("TARGET_IP") or "127.0.0.1"
    port = int(os.environ.get("AUTOSEC_DOIP_PORT", "13400"))
    try:
        with socket.create_connection((host, port), timeout=1.5) as sock:
            sock.settimeout(1.0)
            sock.sendall(b"\x02\xfd\x00\x05\x00\x00\x00\x00")
            print(f"[RESULT] sent zero-length DoIP routing pre-check to {host}:{port}")
            return True
    except OSError as exc:
        print(f"[INFO] DoIP routing pre-check skipped: {exc}")
        return False


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc135DoipRoutingActivationProbePlugin(IVIVulnerabilityPlugin):
    meta_poc_name = 'DoIP Routing Activation 前置条件检测'
    meta_cve_id = 'CWE-306'
    meta_severity = 'Medium'
    meta_protocol = 'doip'
    meta_target_os = ['all']
    meta_required_params = ['target_ip']
    meta_profiles = ['network']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = 'Probe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

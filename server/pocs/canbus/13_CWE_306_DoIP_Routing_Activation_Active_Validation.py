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


VULN = {
    "id":             0,
    "cve":            "CWE-306",
    "year":           306,
    "domain":         "canbus",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "DoIP Routing Activation 前置条件检测",
    "source_url":     "https://cwe.mitre.org/data/definitions/306.html",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://cwe.mitre.org/data/definitions/306.html"],
    "signature_tokens": ["CWE-306"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CWE-306 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CWE-306") if vuln else "CWE-306",
        "target":    getattr(plugin, "target_ip", "unknown"),
        "technique": "legacy exploit() wrapper",
        "raw":       str(result)[:300],
    }

    # 根据是否有主动网络调用推断等级
    level = "B" if vulnerable is True else ("C" if vulnerable is False else "D")
    try:
        from probe_utils import detection_confidence as _detection_confidence
        return _detection_confidence(level, evidence, vulnerable=vulnerable)
    except ImportError:
        return {
            "detection_confidence": {
                "level": level, "vulnerable": vulnerable,
                "evidence": evidence, "method": "legacy_wrapper",
            }
        }


class Poc135DoipRoutingActivationProbePlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-CAN-013"
    meta_poc_name = 'CWE-306 DoIP Routing Activation Active Validation'
    meta_cve_id = 'CWE-306'
    meta_source_url = 'https://cwe.mitre.org/data/definitions/306.html'
    meta_references = ['https://cwe.mitre.org/data/definitions/306.html']
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

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "13_DoIP_Routing_Activation_Audit") if "VULN" in dir() else "13_DoIP_Routing_Activation_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc135DoipRoutingActivationProbePlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

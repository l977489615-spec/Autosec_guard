#!/usr/bin/env python3
"""Safe DoIP entity status probe template."""
from __future__ import annotations

import os
import socket

POC_TAG = "134. DoIP Entity Status 安全探测"


def run_check() -> bool:
    host = os.environ.get("AUTOSEC_TARGET_IP") or os.environ.get("TARGET_IP") or "127.0.0.1"
    port = int(os.environ.get("AUTOSEC_DOIP_PORT", "13400"))
    try:
        with socket.create_connection((host, port), timeout=1.5):
            print(f"[RESULT] DoIP port reachable: {host}:{port}")
            return True
    except OSError as exc:
        print(f"[INFO] DoIP port not reachable: {host}:{port} ({exc})")
        return False


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


VULN = {
    "id":             0,
    "cve":            "CWE-200",
    "year":           200,
    "domain":         "canbus",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "DoIP Entity Status 安全探测",
    "source_url":     "https://cwe.mitre.org/data/definitions/200.html",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://cwe.mitre.org/data/definitions/200.html"],
    "signature_tokens": ["CWE-200"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CWE-200 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CWE-200") if vuln else "CWE-200",
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


class Poc134DoipEntityStatusProbePlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-CAN-012"
    meta_poc_name = 'CWE-200 DoIP Entity Status 安全探测 Active Validation'
    meta_cve_id = 'CWE-200'
    meta_source_url = 'https://cwe.mitre.org/data/definitions/200.html'
    meta_references = ['https://cwe.mitre.org/data/definitions/200.html']
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

    _desc = VULN.get("summary", "12_DoIP_Entity_Status_Audit") if "VULN" in dir() else "12_DoIP_Entity_Status_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc134DoipEntityStatusProbePlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

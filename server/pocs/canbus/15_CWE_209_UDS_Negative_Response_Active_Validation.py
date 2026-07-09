#!/usr/bin/env python3
"""Offline lint for UDS negative response logs."""
from __future__ import annotations

import os
import re
from pathlib import Path

POC_TAG = "137. UDS 负响应与安全访问日志检测"


def run_check() -> bool:
    path = Path(os.environ.get("AUTOSEC_UDS_LOG_FIXTURE", ""))
    text = path.read_text(encoding="utf-8", errors="ignore") if path.is_file() else os.environ.get("AUTOSEC_UDS_LOG_TEXT", "")
    if not text:
        print("[INFO] no UDS log fixture supplied")
        return False
    hit = bool(re.search(r"\b7F\s+(27|10|11|22|31)\s+(33|35|36|37|78)\b", text, re.I))
    print("[RESULT] security-relevant UDS negative response:", "FOUND" if hit else "not found")
    return hit


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


VULN = {
    "id":             0,
    "cve":            "CWE-209",
    "year":           209,
    "domain":         "canbus",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "UDS 负响应与安全访问日志检测",
    "source_url":     "https://cwe.mitre.org/data/definitions/209.html",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://cwe.mitre.org/data/definitions/209.html"],
    "signature_tokens": ["CWE-209"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CWE-209 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CWE-209") if vuln else "CWE-209",
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


class Poc137UdsNegativeResponseLintPlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-CAN-015"
    meta_poc_name = 'CWE-209 UDS Negative Response Active Validation'
    meta_cve_id = 'CWE-209'
    meta_source_url = 'https://cwe.mitre.org/data/definitions/209.html'
    meta_references = ['https://cwe.mitre.org/data/definitions/209.html']
    meta_severity = 'Medium'
    meta_protocol = 'uds'
    meta_target_os = ['all']
    meta_required_params = ['uds_log_fixture']
    meta_profiles = ['can_extended']
    meta_attack_surface = 'CAN/UDS/OBD'
    is_disruptive = False
    meta_destructive_level = 'Safe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "15_UDS_Negative_Response_Audit") if "VULN" in dir() else "15_UDS_Negative_Response_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc137UdsNegativeResponseLintPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

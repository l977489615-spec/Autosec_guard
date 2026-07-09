#!/usr/bin/env python3
"""Offline lint for CAN replay logs before any bus transmission."""
from __future__ import annotations

import os
import re
from pathlib import Path

POC_TAG = "136. CAN 重放日志安全 Lint"


def run_check() -> bool:
    path = Path(os.environ.get("AUTOSEC_CAN_LOG_FIXTURE", ""))
    if not path.is_file():
        print("[INFO] no CAN log fixture supplied")
        return False
    text = path.read_text(encoding="utf-8", errors="ignore")
    ids = [int(match, 16) for match in re.findall(r"\b([0-7][0-9A-Fa-f]{2})\b", text)]
    suspicious = [hex(can_id) for can_id in ids if can_id < 0x100 or can_id in {0x7DF, 0x7E0, 0x7E8}]
    print("[RESULT] suspicious replay IDs:", suspicious[:20])
    return bool(suspicious)


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


VULN = {
    "id":             0,
    "cve":            "CWE-294",
    "year":           294,
    "domain":         "canbus",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "CAN 重放日志安全 Lint",
    "source_url":     "https://cwe.mitre.org/data/definitions/294.html",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://cwe.mitre.org/data/definitions/294.html"],
    "signature_tokens": ["CWE-294"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CWE-294 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CWE-294") if vuln else "CWE-294",
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


class Poc136CanLogReplaySafetyLintPlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-CAN-014"
    meta_poc_name = 'CWE-294 CAN 重放日志安全 Lint Active Validation'
    meta_cve_id = 'CWE-294'
    meta_source_url = 'https://cwe.mitre.org/data/definitions/294.html'
    meta_references = ['https://cwe.mitre.org/data/definitions/294.html']
    meta_severity = 'Medium'
    meta_protocol = 'can'
    meta_target_os = ['all']
    meta_required_params = ['can_log_fixture']
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

    _desc = VULN.get("summary", "14_CAN_Log_Replay_Safety_Audit") if "VULN" in dir() else "14_CAN_Log_Replay_Safety_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc136CanLogReplaySafetyLintPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

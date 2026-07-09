#!/usr/bin/env python3
"""CVE-2023-45779 – Android APEX signing key reuse / APEX factory supply-chain attack.

Public PoC source: https://github.com/metaredteam/rtx-cve-2023-45779
  apex-checker/check.sh  (Meta Red Team X, 2023)

Technique:
  Android APEXes shipped with devices must be signed with OEM-private keys.
  CVE-2023-45779 covers devices where the APEXes are signed with test/AOSP
  public keys (i.e. keys whose private halves are available in AOSP source).
  An attacker can:
    1. Re-sign any AOSP module with the same test key.
    2. Push it via "adb install" or "adb sync".
    3. The device accepts the update because the APK/AVB key matches.

  check.sh verifies each .apex by:
    apksigner verify --print-certs → SHA-256 compared against list of public APK keys
    unzip -p apex_pubkey | sha256sum  → compared against list of public AVB keys

This plugin runs the check.sh logic in Python against all .apex files on
a connected ADB device (or against a supplied directory).
"""
from __future__ import annotations

import hashlib
import io
import os
import subprocess
import tempfile
from pathlib import Path
from zipfile import ZipFile, BadZipFile

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 14,
    "cve": "CVE-2023-45779",
    "year": 2023,
    "domain": "application",
    "vendor_product": "Android APEX signing / AOSP build chain",
    "component": "APEX APK + AVB key validation in device update path",
    "type": "Signing-key reuse → privilege escalation / supply-chain attack",
    "summary": (
        "OEM devices shipped with APEX modules signed by public AOSP test keys "
        "allow any attacker with physical USB access to replace system components "
        "without triggering signature verification failures."
    ),
    "source_url": "https://github.com/metaredteam/rtx-cve-2023-45779",
    "requires_manual_review": True,
    "affected": [{"vendor": "Various OEMs", "product": "Android",
                  "versions": [{"version": "pre-2023-12 patch", "status": "affected"}]}],
}

POC_REPO  = Path(__file__).parent.parent.parent / \
    "public_poc_sources/repos/metaredteam__rtx-cve-2023-45779"
CHECK_SH  = POC_REPO / "apex-checker" / "check.sh"
COMMON_SH = POC_REPO / "apex-checker" / "common.sh"

# Known AOSP public APK signing certificate SHA-256 fingerprints (from public keystore)
AOSP_PUBLIC_APK_KEYS = {
    # test-keys (from build/target/product/security/)
    "a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc",
    "7f3d77e5feeb8d11d89b4b29194ebde695f44cb4a5a2f1e73c64dbf11c5c3d14",
    # platform key fingerprint (commonly used AOSP)
    "f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83",
}
# Known AOSP public AVB signing key SHA-256 (apex_pubkey inside APEX zip)
AOSP_PUBLIC_AVB_KEYS = {
    "bd1f1c4f04e73ee9fdb55b31d87eb92dbb1bfed0bcde36a29e527bce02a9a4e6",
    "dbd9d6ab338e4b4e8b5d13f6c19bcbeeb9acaeee68d5e26b9a3b89085b7d59e5",
}


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _extract_apex_pubkey(apex_path: str) -> str | None:
    """Extract apex_pubkey from the APEX zip and return its SHA-256."""
    try:
        with ZipFile(apex_path) as z:
            return _sha256_bytes(z.read("apex_pubkey"))
    except (BadZipFile, KeyError):
        return None


def _get_apk_cert_sha256(apex_path: str) -> str | None:
    """Run apksigner to get APK signing cert SHA-256 (if available)."""
    try:
        out = subprocess.check_output(
            ["apksigner", "verify", "--print-certs", apex_path],
            stderr=subprocess.DEVNULL, timeout=20, text=True,
        )
        for line in out.splitlines():
            if "SHA-256 digest:" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    return parts[-1].strip()
    except Exception:
        return None
    return None


def _pull_apexes_from_device() -> list[str]:
    """Pull all APEX files from a connected ADB device to a temp dir."""
    tmp = tempfile.mkdtemp(prefix="apex_check_")
    try:
        listing = subprocess.check_output(
            ["adb", "shell", "find", "/system/apex", "/apex", "-name", "*.apex"],
            text=True, timeout=20, stderr=subprocess.DEVNULL,
        )
        paths = [p.strip() for p in listing.splitlines() if p.strip()]
        for remote in paths:
            local = os.path.join(tmp, os.path.basename(remote))
            subprocess.run(
                ["adb", "pull", remote, local],
                capture_output=True, timeout=30,
            )
        return [str(p) for p in Path(tmp).glob("*.apex")]
    except Exception:
        return []


def _run_poc(plugin):
    apex_dir = (plugin.params or {}).get("apex_dir", "")
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    evidence: dict = {
        "cve": "CVE-2023-45779",
        "check_sh_present": CHECK_SH.exists(),
        "vulnerable_apexes": [],
        "checked_count": 0,
    }

    apex_files: list[str] = []
    if apex_dir and Path(apex_dir).exists():
        apex_files = [str(p) for p in Path(apex_dir).glob("*.apex")]
    elif allow_disruptive:
        apex_files = _pull_apexes_from_device()
        evidence["pulled_from_device"] = len(apex_files)

    if not apex_files and CHECK_SH.exists():
        # Dry-run check.sh without actually calling it
        evidence["detail"] = (
            f"check.sh is at {CHECK_SH}. "
            "Supply apex_dir= or run with allow_disruptive=true + ADB device."
        )
    else:
        for apex in apex_files:
            evidence["checked_count"] += 1
            avb_fp  = _extract_apex_pubkey(apex)
            apk_fp  = _get_apk_cert_sha256(apex)
            aosp_avb = avb_fp in AOSP_PUBLIC_AVB_KEYS  if avb_fp else False
            aosp_apk = apk_fp in AOSP_PUBLIC_APK_KEYS  if apk_fp else False
            if aosp_avb or aosp_apk:
                evidence["vulnerable_apexes"].append({
                    "file": os.path.basename(apex),
                    "aosp_avb_key": aosp_avb,
                    "aosp_apk_key": aosp_apk,
                    "avb_sha256":   avb_fp,
                    "apk_sha256":   apk_fp,
                })

    vulnerable = len(evidence["vulnerable_apexes"]) > 0
    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "metaredteam/rtx-cve-2023-45779 / apex-checker/check.sh",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc72CVE202345779ApexSigningKeyReuseSupplyChainAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-APP-072"
    meta_poc_name   = 'CVE-2023-45779 Android APEX Signing Key Reuse Active Validation'
    meta_cve_id     = "CVE-2023-45779"
    meta_severity   = "Critical"
    meta_protocol   = "local"
    meta_target_os  = ["android"]
    meta_required_params = []
    meta_optional_params = ["apex_dir", "allow_disruptive"]
    meta_profiles   = ["application"]
    meta_source_url = "https://github.com/metaredteam/rtx-cve-2023-45779"
    meta_references       = ['https://github.com/metaredteam/rtx-cve-2023-45779']
    meta_attack_surface = "Android APEX test/AOSP signing key reuse privilege escalation"
    is_disruptive   = False
    meta_destructive_level = "Safe"

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

    _desc = VULN.get("summary", "72_Android_APEX_signing_deployment_Android_APEX_signing_Audit") if "VULN" in dir() else "72_Android_APEX_signing_deployment_Android_APEX_signing_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc72CVE202345779ApexSigningKeyReuseSupplyChainAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

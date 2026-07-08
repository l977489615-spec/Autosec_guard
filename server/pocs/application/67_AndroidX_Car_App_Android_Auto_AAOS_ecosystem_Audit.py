#!/usr/bin/env python3
"""CVE-2024-10382 – AndroidX CarAppService Binder deserialization type confusion.

Public PoC reference: https://github.com/metaredteam/rtx-cve-2024-10382 (Meta Red Team X)
Technique:
  CarAppService uses a custom ICarAppHost Binder interface to exchange
  ParcelableWrapper objects with the host app (Android Auto head unit or AAOS).
  A crafted IPC call sends a Parcel containing a class token for a non-Parcelable
  type (e.g. Intent with nested data) where the service expects a specific
  ParcelableWrapper subclass.
  The type-confusion during Parcel.readParcelable() leads to arbitrary method
  dispatch → heap corruption or ClassCastException-based exploit chain
  against the car app process.

Adapted approach:
  Plugin uses ADB to push a crafted Binder client APK that sends the
  malformed IPC payload.  Without the APK, it checks whether a vulnerable
  car app version is installed and reports risk.
"""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 16,
    "cve": "CVE-2024-10382",
    "year": 2024,
    "domain": "application",
    "vendor_product": "AndroidX CarAppService / Android Auto / AAOS",
    "component": "CarAppService Binder ICarAppHost.sendParcelable",
    "type": "Binder type confusion → process compromise",
    "summary": (
        "Crafted IPC Parcel with mismatched class token causes type confusion "
        "in CarAppService.onBind handler, enabling arbitrary method execution "
        "within the victim car app process."
    ),
    "source_url": "https://github.com/metaredteam/rtx-cve-2024-10382",
    "requires_manual_review": True,
    "affected": [{"vendor": "Google", "product": "AndroidX Car App Library", "versions": [{"version": "<1.4.0", "status": "affected"}]}],
}

# Expected vulnerable library version prefix
VULN_CAR_APP_LIB = "androidx.car.app:car-app"
VULN_VERSION_MAX  = "1.3"

# Binder payload skeleton (non-weaponised; actual exploit requires compiled APK)
_BINDER_PAYLOAD_DESC = {
    "interface_descriptor": "androidx.car.app.ICarAppHost",
    "transaction_code": 2,          # sendParcelable
    "parcel_structure": [
        {"field": "interface_token", "value": "androidx.car.app.ICarAppHost"},
        {"field": "class_token",     "value": "android.content.Intent",
         "note": "type-confusion: service expects ParcelableWrapper, gets Intent"},
        {"field": "intent_action",   "value": "android.intent.action.VIEW"},
        {"field": "intent_data",     "value": "content://com.evil/cmd?exec=id"},
    ],
}


def _check_car_app_version_via_adb() -> dict:
    """Check car app library version on connected device via ADB dumpsys."""
    result = {"found": False, "version": None, "vulnerable": False}
    try:
        out = subprocess.check_output(
            ["adb", "shell", "dumpsys", "package", "com.google.android.projection.gearhead"],
            text=True, timeout=20, stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines():
            if "versionName" in line:
                ver = line.split("=")[-1].strip()
                result["found"]     = True
                result["version"]   = ver
                result["vulnerable"] = ver < "10.0"  # rough check
                break
    except Exception as exc:
        result["detail"] = str(exc)
    return result


def _check_car_app_aidl_exposed() -> dict:
    """Check whether ICarAppHost is exposed on a connected device."""
    result = {"exposed": False, "detail": ""}
    try:
        out = subprocess.check_output(
            ["adb", "shell", "service", "list"],
            text=True, timeout=20, stderr=subprocess.DEVNULL,
        )
        result["exposed"] = "car_app" in out.lower() or "carapp" in out.lower()
        result["detail"]  = "ICarAppHost service found" if result["exposed"] else "Not found in service list"
    except Exception as exc:
        result["detail"] = str(exc)
    return result


def _run_poc(plugin):
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    aidl   = _check_car_app_aidl_exposed()
    car_ver = _check_car_app_version_via_adb()

    evidence = {
        "cve": "CVE-2024-10382",
        "icarapphost_exposed": aidl["exposed"],
        "aidl_detail":         aidl["detail"],
        "car_app_found":       car_ver["found"],
        "car_app_version":     car_ver["version"],
        "car_app_vulnerable":  car_ver.get("vulnerable"),
        "binder_payload_desc": _BINDER_PAYLOAD_DESC,
        "exploit_requires":    "Compiled Binder client APK (see metaredteam/rtx-cve-2024-10382)",
    }

    if allow_disruptive and aidl["exposed"]:
        evidence["would_send"] = (
            "adb shell am startservice -n <victim_pkg>/.CarAppService "
            "--el binder_payload <crafted_parcel_hex>"
        )

    vulnerable = aidl["exposed"] or car_ver.get("vulnerable", False)
    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": True,
        "poc_source": "metaredteam/rtx-cve-2024-10382 / AndroidX CarAppService type confusion",
    }


class Poc67CVE202410382CarAppServiceBinderTypeConfusionAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-APP-067"
    meta_poc_name   = "CVE-2024-10382 AndroidX CarAppService Binder Type Confusion"
    meta_cve_id     = "CVE-2024-10382"
    meta_severity   = "High"
    meta_protocol   = "local"
    meta_target_os  = ["android"]
    meta_required_params = []
    meta_optional_params = ["allow_disruptive"]
    meta_profiles   = ["application"]
    meta_source_url = "https://github.com/metaredteam/rtx-cve-2024-10382"
    meta_attack_surface = "AndroidX CarAppService IPC Binder type confusion"
    is_disruptive   = True
    meta_destructive_level = "Disruptive"

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

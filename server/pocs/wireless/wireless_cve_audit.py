"""Shared wireless audit helpers.

These helpers are intentionally conservative: they actively collect local/ADB
evidence that a target is in an affected family, but they do not emit
weaponized over-the-air exploit payloads on their own.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from typing import Any


def as_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on", "enabled"}:
        return True
    if text in {"0", "false", "no", "n", "off", "disabled"}:
        return False
    return None


def version_tuple(value: str) -> tuple[int, ...] | None:
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", value or "")
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())


def _run(command: list[str], timeout: int = 8) -> str:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return (result.stdout or result.stderr or "").strip()


def _extract_version(text: str) -> str:
    match = re.search(r"\d+(?:\.\d+){1,3}", text or "")
    return match.group(0) if match else (text or "").strip()


def local_version(explicit: Any, binary: str, *args: str) -> str:
    if explicit not in (None, ""):
        return str(explicit).strip()
    if not shutil.which(binary):
        return ""
    try:
        return _extract_version(_run([binary, *args]))
    except Exception:
        return ""


def _adb_shell(serial: str, *args: str) -> str:
    if not serial or not shutil.which("adb"):
        return ""
    try:
        return _run(["adb", "-s", serial, "shell", *args])
    except Exception:
        return ""


def _android_version_key(release: str) -> str:
    match = re.search(r"(\d+(?:\.\d+)?)", release or "")
    return match.group(1) if match else ""


def _capability_enabled(required_capability: str, capability_value: Any, service_text: str) -> bool:
    parsed = as_bool(capability_value)
    if parsed is not None:
        return parsed

    lowered = (service_text or "").lower()
    if not lowered:
        return False

    token_map = {
        "hfp_enabled": ("hfp", "handsfree", "headsetclient", "headset"),
        "pbap_enabled": ("pbap", "phonebook"),
        "eap_pwd_enabled": ("eap-pwd", "eap_pwd"),
        "sae_enabled": ("sae", "wpa3"),
        "ctkd_enabled": ("ctkd", "cross-transport"),
    }
    tokens = token_map.get(required_capability, (required_capability.replace("_enabled", ""),))
    return any(token in lowered for token in tokens)


def android_exposure(
    params: dict[str, Any],
    affected_versions: set[str],
    fixed_bulletin: str,
    required_capability: str | None = None,
) -> tuple[bool, str]:
    serial = str(
        params.get("expected_usb_serial")
        or params.get("usb_device_serial")
        or params.get("serial")
        or ""
    ).strip()

    release = str(params.get("android_version") or "").strip()
    patch = str(params.get("android_security_patch") or "").strip()
    capability_value = params.get(required_capability) if required_capability else None
    capability_source = "parameter" if capability_value not in (None, "") else "unknown"
    service_text = str(
        params.get("bluetooth_service_text")
        or params.get("dumpsys_bluetooth_text")
        or params.get("software_inventory_text")
        or ""
    )

    release_source = "parameter" if release else "unknown"
    patch_source = "parameter" if patch else "unknown"
    service_source = "parameter" if service_text else "unknown"

    if serial:
        if not release:
            release = _adb_shell(serial, "getprop", "ro.build.version.release")
            release_source = "adb:getprop"
        if not patch:
            patch = _adb_shell(serial, "getprop", "ro.build.version.security_patch")
            patch_source = "adb:getprop"
        if not service_text:
            service_text = _adb_shell(serial, "dumpsys", "bluetooth_manager")
            service_source = "adb:dumpsys"

    version_key = _android_version_key(release)
    affected_release = version_key in affected_versions
    patch_observed = bool(re.match(r"\d{4}-\d{2}-\d{2}$", patch or ""))
    patch_missing = patch_observed and patch < fixed_bulletin
    capability_ok = True
    if required_capability:
        capability_ok = _capability_enabled(required_capability, capability_value, service_text)
        if capability_source == "unknown" and service_text:
            capability_source = service_source

    vulnerable = bool(affected_release and capability_ok and patch_missing)
    evidence = (
        f"android_release={release or 'unknown'}; release_source={release_source}; "
        f"android_release_key={version_key or 'unknown'}; affected_release={affected_release}; "
        f"security_patch={patch or 'unknown'}; patch_source={patch_source}; "
        f"fixed_bulletin={fixed_bulletin}; patch_missing={patch_missing}; "
        f"required_capability={required_capability or 'none'}; capability_enabled={capability_ok}; "
        f"capability_source={capability_source}; serial={serial or 'none'}."
    )
    if service_text:
        excerpt = " ".join(service_text.split())[:180]
        evidence += f" dumpsys_bluetooth_excerpt={excerpt!r}."
    if not patch_observed:
        evidence += " Android security patch level was not observed; exposure could not be fully confirmed."
    return vulnerable, evidence

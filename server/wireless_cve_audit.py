"""Shared helpers for non-destructive wireless CVE exposure audits."""
from __future__ import annotations

import re
import shutil
import subprocess
from datetime import date


def version_tuple(value: str) -> tuple[int, ...]:
    match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", value or "")
    if not match:
        return ()
    return tuple(int(part or 0) for part in match.groups())


def as_bool(value):
    if value in (True, "true", "True", "1", 1, "yes", "enabled"):
        return True
    if value in (False, "false", "False", "0", 0, "no", "disabled"):
        return False
    return None


def run(command: list[str], timeout: int = 8) -> str:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return ((result.stdout or "") + "\n" + (result.stderr or "")).strip()


def local_version(param_value, binary: str, *args: str) -> str:
    explicit = str(param_value or "").strip()
    if explicit:
        return explicit
    path = shutil.which(binary)
    return run([path, *args]) if path else ""


def parse_patch_date(value: str) -> date | None:
    match = re.search(r"(\d{4})-(\d{2})-(\d{2})", value or "")
    if not match:
        return None
    try:
        return date(*(int(part) for part in match.groups()))
    except ValueError:
        return None


def android_facts(params: dict) -> tuple[str, str, str]:
    version = str(params.get("android_version") or "").strip()
    patch = str(params.get("android_security_patch") or "").strip()
    source = "parameter"
    serial = str(
        params.get("expected_usb_serial")
        or params.get("usb_device_serial")
        or ""
    ).strip()
    if serial and shutil.which("adb"):
        if not version:
            version = run(
                ["adb", "-s", serial, "shell", "getprop", "ro.build.version.release"]
            )
        if not patch:
            patch = run(
                ["adb", "-s", serial, "shell", "getprop", "ro.build.version.security_patch"]
            )
        source = "adb"
    return version.strip(), patch.strip(), source


def android_exposure(
    params: dict,
    affected_versions: set[str],
    fixed_patch: str,
    required_capability: str | None = None,
) -> tuple[bool, str]:
    version, patch, source = android_facts(params)
    normalized_version = version.replace("L", ".1").strip()
    affected = normalized_version in affected_versions
    observed_patch = parse_patch_date(patch)
    fixed_date = parse_patch_date(fixed_patch)
    unpatched = bool(observed_patch and fixed_date and observed_patch < fixed_date)
    patch_unknown = observed_patch is None
    capability = as_bool(params.get(required_capability)) if required_capability else True
    vulnerable = bool(affected and capability is True and unpatched)
    evidence = (
        f"android_version={version or 'unknown'}; security_patch={patch or 'unknown'}; "
        f"facts_source={source}; affected_version={affected}; fixed_patch={fixed_patch}; "
        f"required_capability={required_capability or 'none'}; "
        f"capability_enabled={capability}; patch_unknown={patch_unknown}. "
        "No malformed Bluetooth packet was transmitted."
    )
    if affected and patch_unknown:
        evidence += " Patch level is unavailable, so exposure was not confirmed."
    return vulnerable, evidence

"""APK 拉取 / Manifest 提取 / 正则判定（供 poc10–12 等静态检测复用）。"""
from __future__ import annotations

import os
import re
import shutil
from typing import Callable, Optional

from .common import ADB_CMD, run_cmd, resolve_adb_serial

CANDIDATE_REMOTE_PATHS = [
    "/system/priv-app/CarSetting/CarSetting.apk",
    "/system/priv-app/DownloadProvider/DownloadProvider.apk",
]
LOCAL_APK_NAMES = [os.path.basename(path) for path in CANDIDATE_REMOTE_PATHS]


def _remote_path_exists(device: str, path: str) -> bool:
    code, out = run_cmd([ADB_CMD, "-s", device, "shell", "ls", path], timeout=6.0)
    if code < 0:
        return False
    return "No such file" not in out and "没有那个文件或目录" not in out


def _adb_pull(device: str, remote: str, local: str) -> bool:
    code, _ = run_cmd([ADB_CMD, "-s", device, "pull", remote, local], timeout=120.0)
    return code == 0 and os.path.isfile(local) and os.path.getsize(local) > 0


def _local_apk_in(workdir: str) -> Optional[str]:
    for name in LOCAL_APK_NAMES:
        path = os.path.join(workdir, name)
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            return path
    return None


def _apktool_path(workdir: str) -> Optional[str]:
    local_bat = os.path.join(workdir, "apktool.bat")
    if os.path.isfile(local_bat):
        return os.path.join(workdir, "apktool")
    code, _ = run_cmd(["apktool", "--version"], timeout=3.0)
    if code >= 0:
        return "apktool"
    return None


def _decode_apk(apk_path: str, out_dir: str, workdir: str) -> Optional[str]:
    tool = _apktool_path(workdir)
    manifest = os.path.join(out_dir, "AndroidManifest.xml")
    if os.path.isfile(manifest):
        return manifest
    if tool:
        if tool == "apktool":
            code, _ = run_cmd(["apktool", "d", "-s", "-f", apk_path, "-o", out_dir], timeout=240.0)
        else:
            code, _ = run_cmd([tool + ".bat", "d", "-s", "-f", apk_path, "-o", out_dir], timeout=240.0)
        if code == 0 and os.path.isfile(manifest):
            return manifest
    for aapt in ("aapt2", "aapt"):
        fallback = os.path.join(workdir, f"_manifest_{os.path.basename(apk_path)}.txt")
        code, out = run_cmd([aapt, "dump", "xmltree", apk_path, "AndroidManifest.xml"], timeout=20.0)
        if code == 0 and out:
            with open(fallback, "w", encoding="utf-8", errors="ignore") as handle:
                handle.write(out)
            return fallback
    code, out = run_cmd(["unzip", "-p", apk_path, "AndroidManifest.xml"], timeout=10.0)
    if code == 0 and out:
        fallback = os.path.join(workdir, f"_manifest_{os.path.basename(apk_path)}.xml")
        with open(fallback, "w", encoding="utf-8", errors="ignore") as handle:
            handle.write(out)
        return fallback
    return None


def ensure_manifest(device: str, workdir: str | None = None) -> tuple[Optional[str], str]:
    """返回 (manifest_path, note)。"""
    workdir = workdir or os.getcwd()
    os.makedirs(workdir, exist_ok=True)

    apk_local = _local_apk_in(workdir)
    if not apk_local:
        for remote in CANDIDATE_REMOTE_PATHS:
            if not _remote_path_exists(device, remote):
                continue
            apk_local = os.path.join(workdir, os.path.basename(remote))
            if _adb_pull(device, remote, apk_local):
                break
            apk_local = None
    if not apk_local:
        return None, "未找到本地 APK，且无法从设备 pull CarSetting/DownloadProvider。"

    decoded_dir = os.path.join(workdir, f"decoded_{os.path.basename(apk_local)}_{device.replace(':', '_')}")
    manifest = _decode_apk(apk_local, decoded_dir, workdir)
    if not manifest:
        return None, f"无法从 {apk_local} 提取 AndroidManifest。"

    final_name = f"{device.replace(':', '_')}_{os.path.basename(apk_local)}_AndroidManifest.xml"
    dest = os.path.join(workdir, final_name)
    if os.path.abspath(manifest) != os.path.abspath(dest):
        shutil.copy2(manifest, dest)
    return dest, f"manifest={dest}"


def check_manifest(manifest_path: str, pattern: re.Pattern[str]) -> bool:
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as handle:
            return bool(pattern.search(handle.read()))
    except OSError:
        return False


def run_apk_manifest_check(
    *,
    device_serial: str | None,
    vulnerable_if: Callable[[str], bool],
    workdir: str | None = None,
) -> tuple[bool, str]:
    device = resolve_adb_serial(device_serial)
    if not device:
        return False, "未检测到可用 ADB 设备（需 status=device）。"
    manifest, note = ensure_manifest(device, workdir=workdir)
    if not manifest:
        return False, note
    vulnerable = vulnerable_if(manifest)
    verdict = "VULNERABLE" if vulnerable else "OK"
    return vulnerable, f"{note} | {verdict}"

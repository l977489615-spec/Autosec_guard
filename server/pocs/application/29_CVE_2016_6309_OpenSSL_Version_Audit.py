#!/usr/bin/env python3
"""
PoC Name  : OpenSSL 1.1.0a version audit (CVE-2016-6309)
CVE       : CVE-2016-6309
Category  : application
Severity  : High
Type      : Type-A
Description: Advisory inventory/version check for OpenSSL 1.1.0a exposure.
Prerequisites: USB ADB authorization or operator-supplied software inventory text.
Usage     : python3 29_CVE_2016_6309_OpenSSL_Version_Audit.py <target_ip>
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import tempfile
from typing import List, Optional, Tuple

from advisory_audit_core import run_advisory_audit
from iv_plugin_base import IVIVulnerabilityPlugin

POC_TAG = "24. 检测系统或app是否使用了不安全的openssl（CVE-2016_6309）..."

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

ADB_CMD = "adb"
VULNERABLE_VERSION = "1.1.0a"
OPENSSL_VERSION_REGEX = re.compile(
    r"(OpenSSL |libssl-|SSLv3_|OPENSSL_)(\d+\.\d+\.\d+[a-z]?)",
    re.IGNORECASE,
)
DEVICE_PATHS = [
    "/system/lib/libssl.so",
    "/system/lib64/libssl.so",
    "/vendor/lib/libssl.so",
    "/vendor/lib64/libssl.so",
    "/system/lib/libcrypto.so",
    "/system/lib64/libcrypto.so",
    "/vendor/lib/libcrypto.so",
    "/vendor/lib64/libcrypto.so",
    "/system/lib/libssl.so.1.1",
    "/system/lib64/libssl.so.1.1",
]

VULN = {
    "cve": "CVE-2016-6309",
    "summary": "Detect exposure to OpenSSL 1.1.0a (CVE-2016-6309 denial-of-service) via inventory/version evidence",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2016-6309",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2016-6309"],
    "vendor_product": "OpenSSL",
    "component": "libssl / libcrypto",
    "type": "version_exposure",
    "affected": [
        "openssl 1.1.0a",
        "libssl 1.1.0a",
        "libcrypto 1.1.0a",
        "OpenSSL 1.1.0a",
    ],
    "signature_tokens": [
        "CVE-2016-6309",
        "openssl",
        "libssl",
        "libcrypto",
        "1.1.0a",
    ],
}


def _run_cmd(cmd: List[str], timeout: float = 15.0) -> Tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        out = proc.stdout or proc.stderr or b""
        return proc.returncode, out.decode("utf-8", errors="ignore").strip()
    except Exception as exc:
        return -1, str(exc)


def _list_adb_devices() -> List[str]:
    code, out = _run_cmd([ADB_CMD, "devices"], timeout=4.0)
    if code < 0 or not out:
        return []
    devices = []
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


def _device_file_exists(device: Optional[str], path: str) -> bool:
    cmd = [ADB_CMD]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "ls", path]
    code, out = _run_cmd(cmd, timeout=6.0)
    if code < 0:
        return False
    return "No such file" not in out and "没有那个文件或目录" not in out


def _extract_ascii_sequences(path: str, min_len: int = 4) -> List[str]:
    try:
        data = open(path, "rb").read()
    except OSError:
        return []
    seqs: List[str] = []
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
        elif len(current) >= min_len:
            seqs.append(current.decode("utf-8", errors="ignore"))
            current = bytearray()
    if len(current) >= min_len:
        seqs.append(current.decode("utf-8", errors="ignore"))
    return seqs


def _find_openssl_version(path: str) -> Optional[str]:
    for seq in _extract_ascii_sequences(path):
        match = OPENSSL_VERSION_REGEX.search(seq)
        if match:
            return match.group(2).lower()
    return None


def _collect_device_inventory(device: Optional[str]) -> str:
    lines = [f"adb_device={device or 'auto'}"]
    tmpdir = tempfile.mkdtemp(prefix="openssl_version_audit_")
    try:
        for remote_path in DEVICE_PATHS:
            if not _device_file_exists(device, remote_path):
                continue
            local_path = os.path.join(tmpdir, os.path.basename(remote_path))
            cmd = [ADB_CMD]
            if device:
                cmd += ["-s", device]
            cmd += ["pull", remote_path, local_path]
            code, _ = _run_cmd(cmd, timeout=30.0)
            if code != 0 or not os.path.isfile(local_path):
                continue
            version = _find_openssl_version(local_path)
            lines.append(f"path={remote_path}")
            if version:
                lines.append(f"OpenSSL {version}")
                lines.append(f"libssl-{version}")
            lines.extend(_extract_ascii_sequences(local_path)[:20])
    finally:
        try:
            for name in os.listdir(tmpdir):
                os.remove(os.path.join(tmpdir, name))
            os.rmdir(tmpdir)
        except OSError:
            pass
    return "\n".join(lines)


def _merge_inventory(params: dict, extra: str) -> dict:
    if not extra.strip():
        return params
    merged = dict(params)
    current = str(merged.get("software_inventory_text") or "").strip()
    merged["software_inventory_text"] = "\n".join(part for part in (current, extra) if part).strip()
    return merged


class OpenSSLVersionAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-APP-029"
    meta_poc_name = "CVE-2016-6309 OpenSSL Version Audit"
    meta_cve_id = "CVE-2016-6309"
    meta_source_url = VULN["source_url"]
    meta_references = VULN["references"]
    meta_severity = "High"
    meta_protocol = "local"
    meta_target_os = ["android", "linux"]
    meta_required_params = ["expected_usb_serial"]
    meta_profiles = ["usb_adb", "local_artifact"]
    meta_attack_surface = "第三方组件/高级漏洞"
    is_disruptive = False
    meta_destructive_level = "Probe"

    def check_prerequisites(self) -> bool:
        return True

    def exploit(self):
        params = dict(self.params or {})
        serial = str(params.get("expected_usb_serial") or params.get("usb_device_serial") or "").strip()
        devices = [serial] if serial else _list_adb_devices()
        inventory_chunks = []
        for device in devices[:1]:
            inventory_chunks.append(_collect_device_inventory(device))
        params = _merge_inventory(params, "\n".join(chunk for chunk in inventory_chunks if chunk))
        self.params = params
        return run_advisory_audit(self, VULN)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=VULN["summary"])
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1", help="目标 IP 地址")
    parser.add_argument("--port", default=80, type=int)
    parser.add_argument("--disruptive", action="store_true", help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    plugin = OpenSSLVersionAuditPlugin(
        {
            "target_ip": args.target_ip,
            "port": args.port,
            "allow_disruptive": args.disruptive,
        }
    )
    result = plugin.run_verify()
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))

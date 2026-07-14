#!/usr/bin/env python3
"""Bounded unknown-service fingerprint probe + offline protocol cue.

This is not a fuzzer and does not claim a vulnerability. It executes a small,
allowlisted set of read-only protocol profiles against one authorized TCP port
and records reproducible fingerprint evidence. Format/state inference and
stateful fuzz live in ``protocol_research`` / PoC NET-016.
"""
from __future__ import annotations

import hashlib
import json
import socket
import ssl
import sys
import time
from typing import Any

from iv_plugin_base import IVIVulnerabilityPlugin


MAX_PROFILES = 3
MAX_RESPONSE_BYTES = 4096
MAX_TOTAL_SECONDS = 12.0
ALLOWED_PROFILES = ("passive_banner", "http_head", "tls_handshake")


def _safe_preview(data: bytes, limit: int = 256) -> str:
    return data[:limit].decode("utf-8", errors="backslashreplace")


class DynamicUnknownServiceProbePlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-015"
    meta_poc_name = "Unknown TCP Service Fingerprint Probe"
    meta_cve_id = "CWE-200"
    meta_source_url = "https://cwe.mitre.org/data/definitions/200.html"
    meta_references = [meta_source_url]
    meta_severity = "Info"
    meta_protocol = "tcp"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip", "target_port"]
    meta_profiles = ["recon", "network", "unknown_service"]
    is_disruptive = False
    meta_destructive_level = "Probe"

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("target_ip is required")
        try:
            port = int(self.target_port)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("target_port must be an integer") from exc
        if not 1 <= port <= 65535:
            raise RuntimeError("target_port must be between 1 and 65535")
        self.target_port = port
        self.timeout = max(0.5, min(float(self.timeout or 3), 5.0))
        self.profiles = self._validated_profiles(self.params.get("probe_profiles"))
        return True

    @staticmethod
    def _validated_profiles(value: Any) -> list[str]:
        if isinstance(value, str):
            try:
                decoded = json.loads(value)
                value = decoded if isinstance(decoded, list) else [value]
            except json.JSONDecodeError:
                value = [part.strip() for part in value.split(",")]
        if not isinstance(value, list) or not value:
            value = ["passive_banner"]
        profiles = list(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))
        if len(profiles) > MAX_PROFILES or any(item not in ALLOWED_PROFILES for item in profiles):
            raise RuntimeError("probe_profiles contains a non-allowlisted or excessive profile set")
        return profiles

    def _connect(self) -> socket.socket:
        sock = socket.create_connection((self.target_ip, self.target_port), timeout=self.timeout)
        sock.settimeout(self.timeout)
        return sock

    def _passive_banner(self) -> dict[str, Any]:
        with self._connect() as sock:
            try:
                data = sock.recv(MAX_RESPONSE_BYTES)
            except socket.timeout:
                data = b""
        return self._observation("passive_banner", data)

    def _http_head(self) -> dict[str, Any]:
        request = (
            f"HEAD / HTTP/1.0\r\nHost: {self.target_ip}\r\n"
            "User-Agent: AutoSec-ReadOnly-Probe/3.0\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        with self._connect() as sock:
            sock.sendall(request)
            data = sock.recv(MAX_RESPONSE_BYTES)
        observation = self._observation("http_head", data)
        first_line = data.splitlines()[0][:160] if data else b""
        observation["protocol_match"] = first_line.startswith(b"HTTP/")
        return observation

    def _tls_handshake(self) -> dict[str, Any]:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with self._connect() as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=self.target_ip) as tls_sock:
                cert = tls_sock.getpeercert(binary_form=True) or b""
                return {
                    "profile": "tls_handshake",
                    "protocol_match": True,
                    "tls_version": tls_sock.version(),
                    "cipher": list(tls_sock.cipher() or ()),
                    "certificate_sha256": hashlib.sha256(cert).hexdigest() if cert else "",
                    "certificate_bytes": len(cert),
                }

    @staticmethod
    def _observation(profile: str, data: bytes) -> dict[str, Any]:
        return {
            "profile": profile,
            "received_bytes": len(data),
            "response_sha256": hashlib.sha256(data).hexdigest() if data else "",
            "preview": _safe_preview(data),
            "protocol_match": None,
        }

    def exploit(self):
        started = time.monotonic()
        observations: list[dict[str, Any]] = []
        for profile in self.profiles:
            if time.monotonic() - started >= MAX_TOTAL_SECONDS:
                observations.append({"profile": profile, "status": "budget_exhausted"})
                break
            try:
                handler = getattr(self, f"_{profile}")
                observations.append({"status": "completed", **handler()})
            except (socket.timeout, TimeoutError):
                observations.append({"profile": profile, "status": "timeout"})
            except (ConnectionError, OSError, ssl.SSLError) as exc:
                observations.append({
                    "profile": profile,
                    "status": "protocol_mismatch_or_connection_error",
                    "error_type": type(exc).__name__,
                })

        evidence = {
            "evidence_type": "service_fingerprint",
            "target": self.target_ip,
            "target_port": self.target_port,
            "transport": "tcp",
            "profiles": self.profiles,
            "observations": observations,
            "budget": {
                "max_profiles": MAX_PROFILES,
                "max_response_bytes_per_profile": MAX_RESPONSE_BYTES,
                "max_total_seconds": MAX_TOTAL_SECONDS,
            },
            "conclusion": "Fingerprint evidence only; no vulnerability conclusion is made.",
        }
        self.results.update({
            "vulnerable": False,
            "description": "授权目标单端口的受限服务指纹探测",
            "evidence": json.dumps(evidence, ensure_ascii=False),
            "verification_status": "fingerprint_collected",
            "confidence": "informational",
        })
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 15_CWE_200_Service_Probe_Active_Validation.py <target_ip> <target_port>")
        raise SystemExit(1)
    DynamicUnknownServiceProbePlugin({
        "target_ip": sys.argv[1],
        "target_port": int(sys.argv[2]),
    }).run_verify()

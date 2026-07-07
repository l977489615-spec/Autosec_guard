"""Active validation helpers for IVI vulnerability PoCs.

The helper intentionally separates three evidence levels:

1. passive exposure evidence from inventory/banner/config/SBOM;
2. active protocol observation such as TCP/HTTP/Redis behavior;
3. operator-authorized trigger payload observation for lab validation.

Disruptive trigger payloads are never sent unless the caller explicitly sets
allow_disruptive=true and provides the payload through parameters. This keeps
the PoC framework usable for real validation while preserving an auditable
operator decision point.
"""
from __future__ import annotations

import json
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlparse

from advisory_audit_core import run_advisory_audit


DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "http2": 443,
    "redis": 6379,
}


def run_active_validation(plugin: Any, vuln: dict[str, Any], *, probe: Any = None) -> dict[str, Any]:
    passive = run_advisory_audit(plugin, vuln)
    params = plugin.params or {}
    mode = str(params.get("validation_mode") or params.get("scan_mode") or "probe").lower()
    if mode in {"passive", "inventory", "exposure"}:
        return _merge_result(passive, {
            "validation_mode": mode,
            "active_validation": "disabled_by_request",
        })

    observations: list[dict[str, Any]] = []
    if callable(probe):
        try:
            observations.append({"kind": "custom_probe", **(probe(plugin, vuln) or {})})
        except Exception as exc:
            observations.append({"kind": "custom_probe", "ok": False, "error": str(exc)})
    else:
        observations.extend(_generic_active_observations(plugin, vuln))

    trigger_result = _authorized_trigger_payload(plugin, vuln)
    if trigger_result:
        observations.append(trigger_result)

    active_hit = any(item.get("vulnerable") is True for item in observations)
    active_inconclusive = any(item.get("requires_manual_review") for item in observations)
    vulnerable = bool(passive.get("vulnerable") or active_hit)
    if active_inconclusive and not active_hit:
        vulnerable_value: bool | None = None
    else:
        vulnerable_value = vulnerable

    evidence = _decode_evidence(passive.get("evidence"))
    evidence.update({
        "validation_mode": mode,
        "active_observations": observations,
        "active_observation_count": len(observations),
        "active_vulnerability_observed": active_hit,
        "manual_confirmation_required": bool(active_inconclusive),
        "operator_observation_targets": _operator_observation_targets(vuln),
    })

    return {
        "vulnerable": vulnerable_value,
        "cve_id": passive.get("cve_id") or vuln.get("cve", ""),
        "description": passive.get("description") or vuln.get("summary", ""),
        "evidence": json.dumps(evidence, ensure_ascii=False),
        "requires_manual_review": bool(active_inconclusive),
    }


def _generic_active_observations(plugin: Any, vuln: dict[str, Any]) -> list[dict[str, Any]]:
    params = plugin.params or {}
    target_ip = str(params.get("target_ip") or params.get("host") or "").strip()
    if not target_ip:
        return [{"kind": "active_probe", "ok": False, "reason": "target_ip not provided"}]

    protocol = str(getattr(plugin, "meta_protocol", "") or vuln.get("protocol") or "").lower()
    target_port = _resolve_port(params, protocol)
    if not target_port:
        return [{"kind": "active_probe", "ok": False, "reason": "target_port not provided and cannot infer from protocol"}]

    observations = [_tcp_liveness(target_ip, target_port, params)]
    if protocol in {"http", "https", "http2"}:
        observations.append(_http_observation(target_ip, target_port, protocol, params, vuln))
    elif protocol == "redis":
        observations.append(_redis_observation(target_ip, target_port, params))
    return observations


def _resolve_port(params: dict[str, Any], protocol: str) -> int | None:
    for key in ("target_port", "port"):
        value = params.get(key)
        if value not in (None, ""):
            try:
                return int(value)
            except Exception:
                return None
    candidate_ports = str(params.get("candidate_ports") or "")
    if candidate_ports:
        for item in candidate_ports.split(","):
            item = item.strip()
            if item.isdigit():
                return int(item)
    return DEFAULT_PORTS.get(protocol)


def _tcp_liveness(host: str, port: int, params: dict[str, Any]) -> dict[str, Any]:
    timeout = float(params.get("timeout", 2))
    started = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {
                "kind": "tcp_liveness",
                "ok": True,
                "target": f"{host}:{port}",
                "elapsed_ms": round((time.time() - started) * 1000, 2),
                "phenomenon": "TCP connection established",
            }
    except Exception as exc:
        return {
            "kind": "tcp_liveness",
            "ok": False,
            "target": f"{host}:{port}",
            "error": str(exc),
            "phenomenon": "TCP connection failed",
        }


def _http_observation(host: str, port: int, protocol: str, params: dict[str, Any], vuln: dict[str, Any]) -> dict[str, Any]:
    timeout = float(params.get("timeout", 3))
    use_tls = protocol in {"https", "http2"} or int(port) == 443
    paths = list(params.get("probe_paths") or [])
    if isinstance(paths, str):
        paths = [p.strip() for p in paths.split(",") if p.strip()]
    paths.extend(vuln.get("active_probe_paths") or [])
    paths.append("/")
    path = str(paths[0] or "/")
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: AutoSec-Guard-Validation\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")
    try:
        raw = _send_tcp(host, port, request, timeout=timeout, use_tls=use_tls)
        text = raw.decode("utf-8", errors="replace")
        indicators = []
        for token in ("jwt_secret_key", "agent_secret_key", "config.yaml", "root:", "BEGIN PRIVATE KEY"):
            if token.lower() in text.lower():
                indicators.append(token)
        return {
            "kind": "http_probe",
            "ok": True,
            "path": path,
            "status_line": text.splitlines()[0] if text.splitlines() else "",
            "indicator_hits": indicators,
            "vulnerable": bool(indicators),
            "phenomenon": "HTTP response received; sensitive indicator hits imply exploit confirmation",
        }
    except Exception as exc:
        return {"kind": "http_probe", "ok": False, "path": path, "error": str(exc)}


def _redis_observation(host: str, port: int, params: dict[str, Any]) -> dict[str, Any]:
    timeout = float(params.get("timeout", 3))
    commands = [
        b"*1\r\n$4\r\nPING\r\n",
        b"*2\r\n$7\r\nCOMMAND\r\n$4\r\nINFO\r\n",
    ]
    chunks = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            for command in commands:
                sock.sendall(command)
                try:
                    chunks.append(sock.recv(4096))
                except socket.timeout:
                    chunks.append(b"")
        text = b"\n".join(chunks).decode("utf-8", errors="replace")
        hits = [token for token in ("PONG", "restore", "valkey", "redis") if token.lower() in text.lower()]
        return {
            "kind": "redis_probe",
            "ok": True,
            "indicator_hits": hits,
            "phenomenon": "Redis/Valkey service responded to protocol-level probe",
            "response_excerpt": text[:500],
        }
    except Exception as exc:
        return {"kind": "redis_probe", "ok": False, "error": str(exc)}


def _authorized_trigger_payload(plugin: Any, vuln: dict[str, Any]) -> dict[str, Any] | None:
    params = plugin.params or {}
    payload = params.get("active_payload_hex") or params.get("active_payload_text")
    if not payload:
        return None
    allow = params.get("allow_disruptive") in (True, "true", "True", "1", 1)
    if not allow:
        return {
            "kind": "authorized_trigger",
            "ok": False,
            "requires_manual_review": True,
            "reason": "active payload provided but allow_disruptive=true was not set",
        }
    target_ip = str(params.get("target_ip") or "").strip()
    target_port = _resolve_port(params, str(getattr(plugin, "meta_protocol", "") or ""))
    if not target_ip or not target_port:
        return {"kind": "authorized_trigger", "ok": False, "error": "target_ip/target_port required"}

    before = _tcp_liveness(target_ip, target_port, params)
    try:
        if params.get("active_payload_hex"):
            raw_payload = bytes.fromhex(str(params["active_payload_hex"]).replace(" ", ""))
        else:
            raw_payload = str(params.get("active_payload_text") or "").encode("utf-8", errors="ignore")
        response = _send_tcp(
            target_ip,
            target_port,
            raw_payload,
            timeout=float(params.get("timeout", 3)),
            use_tls=bool(params.get("active_payload_tls")),
        )
        time.sleep(float(params.get("post_trigger_wait_seconds", 1)))
        after = _tcp_liveness(target_ip, target_port, params)
        likely_crash = bool(before.get("ok") and not after.get("ok"))
        return {
            "kind": "authorized_trigger",
            "ok": True,
            "payload_bytes": len(raw_payload),
            "response_excerpt": response[:300].decode("utf-8", errors="replace"),
            "before": before,
            "after": after,
            "vulnerable": likely_crash,
            "requires_manual_review": True,
            "phenomenon": (
                "service became unreachable after operator-authorized payload"
                if likely_crash else
                "payload sent; operator must confirm target-side logs, crash, reset, or state change"
            ),
        }
    except Exception as exc:
        after = _tcp_liveness(target_ip, target_port, params)
        return {
            "kind": "authorized_trigger",
            "ok": False,
            "error": str(exc),
            "before": before,
            "after": after,
            "vulnerable": bool(before.get("ok") and not after.get("ok")),
            "requires_manual_review": True,
            "phenomenon": "payload send caused exception; compare pre/post liveness and target-side logs",
        }


def _send_tcp(host: str, port: int, payload: bytes, *, timeout: float, use_tls: bool = False) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        stream = sock
        if use_tls:
            context = ssl.create_default_context()
            stream = context.wrap_socket(sock, server_hostname=host)
        stream.sendall(payload)
        chunks = []
        try:
            while True:
                chunk = stream.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if sum(len(c) for c in chunks) >= 8192:
                    break
        except socket.timeout:
            pass
        return b"".join(chunks)


def _decode_evidence(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    try:
        return json.loads(str(value or "{}"))
    except Exception:
        return {"raw_evidence": str(value or "")}


def _operator_observation_targets(vuln: dict[str, Any]) -> list[str]:
    text = " ".join(str(vuln.get(k, "")) for k in ("type", "summary", "component")).lower()
    targets = [
        "target service response difference",
        "target-side logs and crash/restart indicators",
    ]
    if any(token in text for token in ("dos", "crash", "null", "overflow")):
        targets.append("process crash, connection reset, watchdog restart, or service unavailability")
    if any(token in text for token in ("can", "uds", "rkes", "keyless", "bluetooth", "rf")):
        targets.append("vehicle/bench physical state, bus frames, pairing state, or RF-visible behavior")
    if any(token in text for token in ("auth", "access", "credential", "path traversal")):
        targets.append("unauthorized data access, privilege change, or sensitive file exposure")
    return targets

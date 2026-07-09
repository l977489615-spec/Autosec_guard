#!/usr/bin/env python3
import argparse
import signal
import socketserver
import struct
import threading
from typing import Callable


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _make_handler(name: str, responder: Callable[[bytes], bytes]):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                data = self.request.recv(4096)
                response = responder(data)
                if response:
                    self.request.sendall(response)
            except Exception:
                return

    Handler.__name__ = f"{name}Handler"
    return Handler


def http_response(data: bytes) -> bytes:
    if data.startswith(b"HEAD "):
        return b"HTTP/1.1 200 OK\r\nServer: AutoSec-IVI\r\nContent-Length: 0\r\n\r\n"
    if b"/metrics" in data:
        return b"HTTP/1.1 404 Not Found\r\nServer: AutoSec-IVI\r\nContent-Length: 0\r\n\r\n"
    body = b"AutoSec mock IVI HTTP service"
    return b"HTTP/1.1 200 OK\r\nServer: AutoSec-IVI\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


def adb_response(data: bytes) -> bytes:
    def adb_packet(command: bytes, arg0: int = 0, arg1: int = 0, payload: bytes = b"") -> bytes:
        cmd_int = struct.unpack("<I", command)[0]
        checksum = sum(payload) & 0xFFFFFFFF
        return struct.pack("<6I", cmd_int, arg0, arg1, len(payload), checksum, cmd_int ^ 0xFFFFFFFF) + payload

    if len(data) >= 24:
        command = data[:4]
        payload_length = struct.unpack("<I", data[12:16])[0]
        payload = data[24:24 + payload_length]
        if command == b"CNXN":
            banner = b"device::ro.product.name=ivi_mock;ro.secure=0\x00"
            return adb_packet(b"CNXN", 0x01000000, 4096, banner)
        if command == b"OPEN" and payload.startswith(b"shell:"):
            local_id = struct.unpack("<I", data[4:8])[0]
            return adb_packet(b"OKAY", 1, local_id, b"")
    if b"host:features" in data:
        return b"OKAYshell_v2,cmd,stat_v2"
    return b""


def rtsp_response(data: bytes) -> bytes:
    if data.startswith(b"ANY /logs?id=0"):
        body = b"logcat: mock ivi debug token accepted"
        return (
            b"RTSP/1.0 200 OK\r\n"
            b"CSeq: 1\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        )
    if data.startswith(b"OPTIONS"):
        return b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n"
    if data.startswith(b"DESCRIBE"):
        return b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\n\r\nv=0\r\ns=AutoSecMock\r\n"
    return b"RTSP/1.0 400 Bad Request\r\nCSeq: 3\r\n\r\n"


def mqtt_response(data: bytes) -> bytes:
    if data.startswith(b"\x10"):
        return b"\x20\x02\x00\x00"
    return b""


def telnet_response(data: bytes) -> bytes:
    if not data or data.strip() == b"":
        return b"IVI login: "
    return b"Password: "


def unknown_response(data: bytes) -> bytes:
    if b"VERSION" in data:
        return b"AUTOSEC-UNKNOWN/1.0 state=ready"
    if data.startswith(b"\x00\x01"):
        return b"ERR invalid frame length"
    return b"OK"


SERVICES = {
    5555: ("adb", adb_response),
    15555: ("adb-alt", adb_response),
    7000: ("rtsp", rtsp_response),
    17000: ("rtsp-alt", rtsp_response),
    1883: ("mqtt", mqtt_response),
    8080: ("http", http_response),
    18080: ("http-alt", http_response),
    19023: ("telnet", telnet_response),
    19090: ("unknown", unknown_response),
    13400: ("doip-like", unknown_response),
    30490: ("someip-like", unknown_response),
    8000: ("qnx-like", unknown_response),
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Start mock vehicle-side services.")
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    servers = []
    for port, (name, responder) in SERVICES.items():
        server = ThreadedTCPServer((args.host, port), _make_handler(name, responder))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        print(f"[mock] {name} listening on {args.host}:{port}")

    stop = threading.Event()

    def _stop(_signum, _frame):
        stop.set()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    stop.wait()
    for server in servers:
        server.shutdown()
        server.server_close()
    print("[mock] stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

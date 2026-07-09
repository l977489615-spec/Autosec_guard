#!/usr/bin/env python3
"""Mock 车端服务集群：尽可能覆盖 recon/network PoC 所需端口与协议。"""
from __future__ import annotations

import argparse
import signal
import socket
import socketserver
import struct
import threading
from typing import Callable


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---------------------------------------------------------------------------
# ADB（CNXN + shell OPEN → OKAY）
# ---------------------------------------------------------------------------

def _adb_packet(command: bytes, arg0: int = 0, arg1: int = 0, payload: bytes = b"") -> bytes:
    cmd_int = struct.unpack("<I", command)[0]
    payload = payload or b""
    checksum = sum(payload) & 0xFFFFFFFF
    header = struct.pack("<6I", cmd_int, arg0, arg1, len(payload), checksum, cmd_int ^ 0xFFFFFFFF)
    return header + payload


def _adb_recv_packet(sock: socket.socket) -> tuple[dict | None, bytes]:
    header = _recv_exact(sock, 24)
    if len(header) < 24:
        return None, b""
    cmd_int, arg0, arg1, length, checksum, magic = struct.unpack("<6I", header)
    payload = _recv_exact(sock, length) if length else b""
    return {
        "command": struct.pack("<I", cmd_int),
        "arg0": arg0,
        "arg1": arg1,
    }, payload


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class ADBHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock = self.request
        sock.settimeout(5)
        try:
            while True:
                packet, payload = _adb_recv_packet(sock)
                if not packet:
                    break
                cmd = packet["command"]
                if cmd == b"CNXN":
                    banner = b"device::ro.product.name=ivi_mock;ro.secure=0;model=AutoSecMock\x00"
                    sock.sendall(_adb_packet(b"CNXN", 0x01000000, 4096, banner))
                elif cmd == b"OPEN" and payload.startswith(b"shell:"):
                    sock.sendall(_adb_packet(b"OKAY", 1, packet["arg0"], b""))
                    sock.sendall(_adb_packet(b"WRTE", 1, packet["arg0"], b"uid=0(root) gid=0(root)\n"))
                elif cmd == b"AUTH":
                    sock.sendall(_adb_packet(b"CNXN", 0x01000000, 4096, b"device::mock\x00"))
                else:
                    break
        except Exception:
            return


# ---------------------------------------------------------------------------
# Telnet（弱口令 root:password / admin:admin）
# ---------------------------------------------------------------------------

WEAK_CREDS = {
    "root": {"password", "root", "123456", "calvin", "toor"},
    "admin": {"admin", "123456", "123", "password"},
    "user": {"user"},
}


class TelnetHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock = self.request
        sock.settimeout(8)
        buf = b""
        user = ""
        stage = "banner"
        try:
            sock.sendall(b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18")  # WILL ECHO, WILL SGA, DO TERM
            sock.sendall(b"IVI mock login: ")
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                buf += chunk
                if stage == "banner" and b"\n" in buf:
                    user = buf.decode("ascii", "ignore").strip().split("\n")[-1].strip()
                    buf = b""
                    sock.sendall(b"Password: ")
                    stage = "password"
                elif stage == "password" and b"\n" in buf:
                    password = buf.decode("ascii", "ignore").strip().split("\n")[-1].strip()
                    if user in WEAK_CREDS and password in WEAK_CREDS[user]:
                        sock.sendall(b"\r\nWelcome to IVI mock\r\n# ")
                    else:
                        sock.sendall(b"\r\nLogin incorrect\r\nIVI mock login: ")
                        user = ""
                        stage = "banner"
                    buf = b""
        except Exception:
            return


# ---------------------------------------------------------------------------
# FTP 匿名登录
# ---------------------------------------------------------------------------

class FTPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock = self.request
        sock.settimeout(5)
        try:
            sock.sendall(b"220 AutoSec Mock FTP ready\r\n")
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                line = data.decode("utf-8", "ignore").strip().upper()
                if line.startswith("USER ANONYMOUS"):
                    sock.sendall(b"331 Anonymous login ok, send password\r\n")
                elif line.startswith("PASS"):
                    sock.sendall(b"230 Login successful.\r\n")
                elif line.startswith("QUIT"):
                    sock.sendall(b"221 Bye\r\n")
                    break
                elif line.startswith("SYST"):
                    sock.sendall(b"215 UNIX Type: L8\r\n")
                else:
                    sock.sendall(b"200 OK\r\n")
        except Exception:
            return


# ---------------------------------------------------------------------------
# 简单响应函数（单次 recv → send）
# ---------------------------------------------------------------------------

def http_response(data: bytes) -> bytes:
    if data.startswith(b"HEAD "):
        return b"HTTP/1.1 200 OK\r\nServer: AutoSec-IVI/1.0\r\nContent-Length: 0\r\n\r\n"
    body = b"AutoSec mock IVI HTTP service"
    return (
        b"HTTP/1.1 200 OK\r\nServer: AutoSec-IVI/1.0\r\nContent-Type: text/plain\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )


def ssh_banner_response(_data: bytes) -> bytes:
    return b"SSH-2.0-AutoSecMockIVI_1.0\r\n"


def rtsp_response(data: bytes) -> bytes:
    if data.startswith(b"ANY /logs?id=0") or b"/logs?id=0" in data:
        body = b"logcat: mock ivi debug token accepted"
        return (
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\n\r\n"
            + body
        )
    if data.startswith(b"OPTIONS"):
        return b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n"
    if data.startswith(b"DESCRIBE"):
        return b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\n\r\nv=0\r\ns=AutoSecMock\r\n"
    return b"RTSP/1.0 200 OK\r\nCSeq: 0\r\n\r\n"


def mqtt_response(data: bytes) -> bytes:
    if data.startswith(b"\x10"):
        return b"\x20\x02\x00\x00"
    if data.startswith(b"\x82"):
        return b"\x90\x03\x00\x01\x00"
    return b""


class MQTTHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock = self.request
        sock.settimeout(5)
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                resp = mqtt_response(data)
                if resp:
                    sock.sendall(resp)
        except Exception:
            return


class DBusHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock = self.request
        sock.settimeout(5)
        try:
            data = sock.recv(4096)
            if not data:
                return
            if data == b"\x00" or data.startswith(b"\x00"):
                sock.sendall(b"OK mock-uuid\r\n")
                data = sock.recv(4096)
            if data and b"AUTH ANONYMOUS" in data:
                sock.sendall(b"OK mock-session\r\n")
            elif data:
                sock.sendall(b"OK\r\n")
        except Exception:
            return


def redis_response(data: bytes) -> bytes:
    if data.startswith(b"PING") or data.startswith(b"ping"):
        return b"+PONG\r\n"
    return b"+OK\r\n"


def modbus_response(_data: bytes) -> bytes:
    return b"\x00\x01\x00\x00\x00\x05\x01\x03\x02\x00\x00"


def hiqnet_response(_data: bytes) -> bytes:
    return b"\xfe\xfd\x00\x0cAutoSecMock"


def doip_response(data: bytes) -> bytes:
    if len(data) >= 8 and data[0:2] == b"\x02\xfd":
        # 路由激活 positive ack
        return b"\x02\xfd\x00\x06\x00\x00\x00\x05" + data[8:12] + b"\x10\x00\x00\x00"
    return b"\x02\xfd\x00\x00\x00\x00\x00\x00"


def unknown_response(data: bytes) -> bytes:
    if b"VERSION" in data or b"version" in data:
        return b"AUTOSEC-UNKNOWN/1.0 state=ready"
    if b"host:version" in data or b"host:features" in data:
        return b"OKAY0028device::ro.product.name=ivi_mock;ro.secure=0"
    if data.startswith(b"\x00\x01"):
        return b"ERR invalid frame length"
    return b"OK mock-service-ready\r\n"


def smtp_banner(_data: bytes) -> bytes:
    return b"220 mock-ivi.local ESMTP AutoSec\r\n"


def generic_ok(_data: bytes) -> bytes:
    return b"OK\r\n"


# ---------------------------------------------------------------------------
# TCP 端口表：(port, name, handler_factory)
# ---------------------------------------------------------------------------

def _make_simple_handler(name: str, responder: Callable[[bytes], bytes]):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                data = self.request.recv(4096)
                response = responder(data or b"")
                if response:
                    self.request.sendall(response)
            except Exception:
                return

    Handler.__name__ = f"{name}Handler"
    return Handler


TCP_SERVICES: list[tuple[int, str, type]] = [
    (21, "ftp", FTPHandler),
    (22, "ssh", _make_simple_handler("ssh", ssh_banner_response)),
    (23, "telnet", TelnetHandler),
    (25, "smtp", _make_simple_handler("smtp", smtp_banner)),
    (80, "http", _make_simple_handler("http", http_response)),
    (102, "s7comm", _make_simple_handler("s7", generic_ok)),
    (443, "https-open", _make_simple_handler("https", http_response)),
    (502, "modbus", _make_simple_handler("modbus", modbus_response)),
    (554, "rtsp-554", _make_simple_handler("rtsp554", rtsp_response)),
    (666, "debug-alt", _make_simple_handler("debug666", unknown_response)),
    (6666, "debug", _make_simple_handler("debug", unknown_response)),
    (6667, "dbus", DBusHandler),
    (1234, "adb-oem", ADBHandler),
    (1883, "mqtt", MQTTHandler),
    (1900, "ssdp-tcp", _make_simple_handler("ssdp-tcp", http_response)),
    (3000, "http-3000", _make_simple_handler("http3000", http_response)),
    (3804, "hiqnet", _make_simple_handler("hiqnet", hiqnet_response)),
    (4040, "http-4040", _make_simple_handler("http4040", http_response)),
    (4444, "adb-4444", ADBHandler),
    (4567, "adb-oem2", ADBHandler),
    (4840, "opcua", _make_simple_handler("opcua", generic_ok)),
    (5000, "http-5000", _make_simple_handler("http5000", http_response)),
    (5555, "adb", ADBHandler),
    (5556, "adb-5556", ADBHandler),
    (5900, "vnc-open", _make_simple_handler("vnc", generic_ok)),
    (6379, "redis", _make_simple_handler("redis", redis_response)),
    (6789, "adb-harmony", ADBHandler),
    (7000, "rtsp", _make_simple_handler("rtsp", rtsp_response)),
    (7777, "adb-mtk", ADBHandler),
    (8000, "qnx-like", _make_simple_handler("qnx", unknown_response)),
    (8080, "http-alt", _make_simple_handler("http-alt", http_response)),
    (8081, "http-8081", _make_simple_handler("http8081", http_response)),
    (8443, "https-alt", _make_simple_handler("https-alt", http_response)),
    (8888, "adb-tool", ADBHandler),
    (8883, "mqtt-tls-open", MQTTHandler),
    (9000, "http-9000", _make_simple_handler("http9000", http_response)),
    (9090, "diag-http", _make_simple_handler("diag", http_response)),
    (9527, "adb-oem-aion", ADBHandler),
    (9999, "adb-tool2", ADBHandler),
    (10000, "oem-svc", _make_simple_handler("oem", unknown_response)),
    (11211, "memcached", _make_simple_handler("memcached", lambda _d: b"VERSION mock-1.0\r\n")),
    (13400, "doip", _make_simple_handler("doip", doip_response)),
    (15555, "adb-alt", ADBHandler),
    (17000, "rtsp-alt", _make_simple_handler("rtsp-alt", rtsp_response)),
    (18080, "http-alt2", _make_simple_handler("http-alt2", http_response)),
    (19023, "telnet-alt", TelnetHandler),
    (19090, "unknown-svc", _make_simple_handler("unknown", unknown_response)),
    (2049, "nfs-open", _make_simple_handler("nfs", generic_ok)),
    (27017, "mongodb-open", _make_simple_handler("mongo", generic_ok)),
    (30490, "someip-tcp", _make_simple_handler("someip-tcp", unknown_response)),
    (61616, "activemq", _make_simple_handler("activemq", generic_ok)),
]


# ---------------------------------------------------------------------------
# UDP 服务（SOME/IP SD、SSDP、mDNS、SNMP）
# ---------------------------------------------------------------------------

def _build_someip_offer() -> bytes:
    entry = struct.pack(
        ">BBHHHBI",
        0x01, 0x00, 0x0000, 0x1234, 0x0001, 0x01, 0xFFFFFFFF,
    )
    sd_payload = struct.pack(">B3sI", 0xC0, b"\x00\x00\x00", len(entry)) + entry + struct.pack(">I", 0)
    payload_len = 8 + len(sd_payload)
    header = struct.pack(
        ">HHIHHBBBB",
        0xFFFF, 0x8100, payload_len, 0xDEAD, 0x0001, 0x01, 0x01, 0x00, 0x00,
    )
    return header + sd_payload


def _udp_someip_loop(host: str, port: int, stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    offer = _build_someip_offer()
    while not stop.is_set():
        try:
            sock.settimeout(1)
            data, addr = sock.recvfrom(65507)
            if data:
                sock.sendto(offer, addr)
        except socket.timeout:
            continue
        except Exception:
            break
    sock.close()


def _udp_ssdp_loop(host: str, port: int, stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    except Exception:
        pass
    sock.bind((host, port))
    location = f"http://{host}:8080/desc.xml"
    response = "\r\n".join([
        "HTTP/1.1 200 OK",
        "CACHE-CONTROL: max-age=1800",
        "EXT:",
        f"LOCATION: {location}",
        "SERVER: AutoSec-Mock-UPnP/1.0",
        "ST: upnp:rootdevice",
        "USN: uuid:autosec-mock-ivi::upnp:rootdevice",
        "", "",
    ]).encode()
    while not stop.is_set():
        try:
            sock.settimeout(1)
            data, addr = sock.recvfrom(4096)
            if b"M-SEARCH" in data or b"NOTIFY" in data or data:
                sock.sendto(response, addr)
        except socket.timeout:
            continue
        except Exception:
            break
    sock.close()


def _udp_mdns_loop(host: str, port: int, stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        mreq = struct.pack("=4s4s", socket.inet_aton("224.0.0.251"), socket.inet_aton(host))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except Exception:
        pass
    sock.bind((host, port))
    # 最小 mDNS 响应（足够触发 PoC 判定）
    response = b"\x00\x00\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00"
    while not stop.is_set():
        try:
            sock.settimeout(1)
            data, addr = sock.recvfrom(4096)
            if data:
                sock.sendto(response, addr)
        except socket.timeout:
            continue
        except Exception:
            break
    sock.close()


def _udp_snmp_loop(host: str, port: int, stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    # 最小 SNMPv1 GetResponse
    response = bytes.fromhex(
        "302602010004067075626c6963a219020400000001020100020100"
        "3007300506030101020500"
    )
    while not stop.is_set():
        try:
            sock.settimeout(1)
            data, addr = sock.recvfrom(4096)
            if data:
                sock.sendto(response, addr)
        except socket.timeout:
            continue
        except Exception:
            break
    sock.close()


UDP_SERVICES = [
    (161, "snmp", _udp_snmp_loop),
    (1900, "ssdp", _udp_ssdp_loop),
    (5353, "mdns", _udp_mdns_loop),
    (30490, "someip-sd", _udp_someip_loop),
]


def start_tcp(host: str, port: int, name: str, handler_cls: type) -> tuple[ThreadedTCPServer | None, str | None]:
    try:
        server = ThreadedTCPServer((host, port), handler_cls)
        threading.Thread(target=server.serve_forever, daemon=True, name=f"tcp-{port}").start()
        print(f"[mock] tcp/{name} listening on {host}:{port}")
        return server, None
    except OSError as exc:
        print(f"[mock] skip tcp/{name} {host}:{port} ({exc})")
        return None, f"{port}/{name}"


def stop_existing_mock() -> int:
    import subprocess
    proc = subprocess.run(
        ["pkill", "-f", "mock_vehicle_services.py"],
        capture_output=True,
        text=True,
    )
    return proc.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Start expanded mock vehicle-side services.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--list", action="store_true", help="列出端口后退出")
    parser.add_argument("--stop", action="store_true", help="停止已在运行的 mock 进程后退出")
    args = parser.parse_args()

    if args.stop:
        stop_existing_mock()
        print("[mock] 已发送停止信号；若端口仍占用，请确认无其他 mock 终端在运行")
        return 0

    if args.list:
        for port, name, _ in TCP_SERVICES:
            print(f"tcp  {port:5d}  {name}")
        for port, name, _ in UDP_SERVICES:
            print(f"udp  {port:5d}  {name}")
        return 0

    tcp_servers: list[ThreadedTCPServer] = []
    skipped: list[str] = []
    for port, name, handler in TCP_SERVICES:
        server, skip = start_tcp(args.host, port, name, handler)
        if server:
            tcp_servers.append(server)
        elif skip:
            skipped.append(skip)

    stop = threading.Event()
    udp_threads: list[threading.Thread] = []
    udp_failed: list[str] = []
    for port, name, loop_fn in UDP_SERVICES:
        try:
            thread = threading.Thread(target=loop_fn, args=(args.host, port, stop), daemon=True, name=f"udp-{port}")
            thread.start()
            udp_threads.append(thread)
            print(f"[mock] udp/{name} listening on {args.host}:{port}")
        except Exception as exc:
            udp_failed.append(f"{port}/{name}")
            print(f"[mock] skip udp/{name} {args.host}:{port} ({exc})")

    print(f"[mock] started {len(tcp_servers)} tcp + {len(UDP_SERVICES) - len(udp_failed)} udp services on {args.host}")
    if skipped:
        print(f"[mock] 警告: {len(skipped)} 个 TCP 端口被占用（常见原因：已有一个 mock 在跑）")
        print("[mock] 处理: 1) 在原 mock 终端按 Ctrl+C  2) 或执行: python3 lab/mock_vehicle_services.py --stop")
        print("[mock] 检查占用: lsof -nP -iTCP:5555 -sTCP:LISTEN")
    print("[mock] Ctrl+C to stop")

    def _stop(_signum, _frame):
        stop.set()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    stop.wait()
    for server in tcp_servers:
        server.shutdown()
        server.server_close()
    print("[mock] stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

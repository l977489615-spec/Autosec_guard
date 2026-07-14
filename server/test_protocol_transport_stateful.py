#!/usr/bin/env python3
from __future__ import annotations

import socket
import threading
import time
import unittest

from protocol_research.transport import DryRunTransportAdapter, TcpStatefulSession, TcpTransportAdapter


class _StatefulMockServer:
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(1)
        self.connections = 0
        self.messages: list[bytes] = []
        self._stop = threading.Event()

    def serve(self) -> None:
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _addr = self.sock.accept()
            except socket.timeout:
                continue
            self.connections += 1
            with conn:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    self.messages.append(data)
                    if data == b"\xff":
                        break
                    conn.sendall(b"\x81" + data[:2])

    def close(self) -> None:
        self._stop.set()
        self.sock.close()


class ProtocolTransportStatefulTests(unittest.TestCase):
    def test_dry_run_reuses_session_across_sequence(self):
        transport = DryRunTransportAdapter(stateful=True)
        transport.play_sequence(["01", "02", "03"])
        self.assertEqual(transport.calls, ["01", "02", "03"])
        self.assertTrue(transport.session_reused)

    def test_tcp_play_sequence_uses_single_connection(self):
        server = _StatefulMockServer()
        thread = threading.Thread(target=server.serve, daemon=True)
        thread.start()
        time.sleep(0.05)
        try:
            transport = TcpTransportAdapter("127.0.0.1", server.port, timeout=1.0, rate_limit_s=0, stateful=True)
            results = transport.play_sequence(["0102", "0304"])
            self.assertEqual(len(results), 2)
            self.assertTrue(all(item.ok for item in results))
            self.assertEqual(results[0].session_id, results[1].session_id)
            self.assertEqual(server.connections, 1)
            self.assertEqual(len(server.messages), 2)
        finally:
            server.close()
            thread.join(timeout=1)

    def test_exchange_still_single_shot(self):
        server = _StatefulMockServer()
        thread = threading.Thread(target=server.serve, daemon=True)
        thread.start()
        time.sleep(0.05)
        try:
            transport = TcpTransportAdapter("127.0.0.1", server.port, timeout=1.0, rate_limit_s=0)
            transport.exchange("aa")
            transport.exchange("bb")
            self.assertEqual(server.connections, 2)
        finally:
            server.close()
            thread.join(timeout=1)


if __name__ == "__main__":
    unittest.main()

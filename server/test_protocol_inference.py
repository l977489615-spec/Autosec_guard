#!/usr/bin/env python3
from __future__ import annotations

import unittest
import sys
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SERVER_DIR))

from protocol_research.corpus import CorpusManager
from protocol_research.field_inference import enrich_symbols, infer_fields_for_samples
from protocol_research.message_clustering import cluster_messages, message_distance


class ProtocolInferenceTests(unittest.TestCase):
    def test_distance_identical_is_zero(self):
        self.assertEqual(message_distance(b"\x01\x00\x00", b"\x01\x00\x00"), 0.0)

    def test_cluster_and_field_inference(self):
        manager = CorpusManager()
        doc = manager.create_from_sessions(
            target={"ip": "192.168.10.20", "port": 18888, "transport": "tcp"},
            sessions=[{
                "session_id": "SESSION-001",
                "messages": [
                    {"index": 0, "direction": "client_to_server", "timestamp": 1.0, "data_hex": "01000008aabbccdd"},
                    {"index": 1, "direction": "server_to_client", "timestamp": 1.1, "data_hex": "8100000400000000"},
                    {"index": 2, "direction": "client_to_server", "timestamp": 1.2, "data_hex": "01000008aabb11ee"},
                    {"index": 3, "direction": "server_to_client", "timestamp": 1.3, "data_hex": "8100000400000001"},
                ],
            }],
        )
        msgs = [m for s in doc.sessions for m in s.messages]
        symbols = enrich_symbols(cluster_messages(msgs))
        self.assertGreaterEqual(len(symbols), 2)
        client_syms = [s for s in symbols if s.direction == "client_to_server"]
        self.assertTrue(client_syms)
        self.assertTrue(client_syms[0].fields)
        self.assertTrue(all(0.0 < f.confidence <= 1.0 for f in client_syms[0].fields))

    def test_length_field_detection(self):
        # bytes[1:3] = uint16_be total length
        samples = [
            bytes.fromhex("010005aabb"),
            bytes.fromhex("010007aabbccdd"),
            bytes.fromhex("010009112233445566"),
        ]
        fields = infer_fields_for_samples(samples)
        types = {f.type for f in fields}
        self.assertIn("length", types)


if __name__ == "__main__":
    unittest.main()

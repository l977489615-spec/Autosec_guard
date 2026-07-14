#!/usr/bin/env python3
from __future__ import annotations

import unittest
import sys
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SERVER_DIR))

from protocol_research.corpus import CorpusManager, CorpusValidationError


class ProtocolCorpusTests(unittest.TestCase):
    def test_create_and_hash_preserves_raw(self):
        manager = CorpusManager()
        doc = manager.create_from_hex_dialog(
            target={"ip": "192.168.10.20", "port": 18888, "transport": "tcp"},
            turns=[
                ("client_to_server", "01000008aabbccdd"),
                ("server_to_client", "8100000400000000"),
            ],
        )
        self.assertTrue(doc.corpus_id.startswith("CORPUS-"))
        self.assertEqual(len(doc.sessions[0].messages), 2)
        self.assertEqual(len(doc.corpus_sha256), 64)
        frozen = doc.corpus_sha256
        # re-freeze must be stable
        doc.freeze_hash()
        self.assertEqual(doc.corpus_sha256, frozen)

    def test_rejects_oversized_message(self):
        manager = CorpusManager(max_message_bytes=8)
        with self.assertRaises(CorpusValidationError):
            manager.create_from_hex_dialog(
                target={"ip": "192.168.10.20", "port": 18888},
                turns=[("client_to_server", "001122334455667788")],
            )


if __name__ == "__main__":
    unittest.main()

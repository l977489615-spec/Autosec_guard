#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import unittest
import sys
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SERVER_DIR))

from protocol_research.corpus_resolver import attach_resolved_corpus, corpus_available_for_params
from protocol_research.corpus_store import ProtocolCorpusStore


class CorpusRefEndToEndTests(unittest.TestCase):
    def test_store_ref_resolves_for_poc_params(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ProtocolCorpusStore(tmp)
            doc = store.save({
                "target": {"ip": "192.168.10.20", "port": 18888, "transport": "tcp"},
                "sessions": [{
                    "session_id": "S1",
                    "messages": [
                        {"index": 0, "direction": "client_to_server", "timestamp": 1.0, "data_hex": "0100"},
                        {"index": 1, "direction": "server_to_client", "timestamp": 1.1, "data_hex": "8100"},
                    ],
                }],
            })
            params = {"corpus_ref": doc.corpus_id, "target_port": 18888}
            self.assertTrue(corpus_available_for_params(
                params,
                store=store,
                target_ip="192.168.10.20",
                target_port=18888,
            ))
            attached = attach_resolved_corpus(params, store=store)
            self.assertIn("corpus", attached)
            self.assertEqual(attached["corpus"]["corpus_id"], doc.corpus_id)

    def test_missing_ref_is_not_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ProtocolCorpusStore(tmp)
            params = {"corpus_ref": "CORPUS-MISSING"}
            self.assertFalse(corpus_available_for_params(params, store=store))


if __name__ == "__main__":
    unittest.main()

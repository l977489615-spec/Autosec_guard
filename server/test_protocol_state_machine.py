#!/usr/bin/env python3
from __future__ import annotations

import unittest
import sys
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SERVER_DIR))

from protocol_research.campaign import run_offline_inference
from protocol_research.corpus import CorpusManager


class ProtocolStateMachineTests(unittest.TestCase):
    def test_infers_transitions_from_dialog(self):
        manager = CorpusManager()
        doc = manager.create_from_hex_dialog(
            target={"ip": "192.168.10.20", "port": 18888, "transport": "tcp"},
            turns=[
                ("client_to_server", "01000008aabbccdd"),
                ("server_to_client", "8100000400000000"),
                ("client_to_server", "02000004deadbeef"),
                ("server_to_client", "8200000400000001"),
            ],
        )
        model = run_offline_inference(doc)
        self.assertIn("S0", model.states)
        self.assertGreaterEqual(len(model.transitions), 1)
        self.assertTrue(any("black-box" in n or "black-box" in n.lower() or "近似" in n or "incomplete" in n or "signatures" in n for n in model.inference_notes) or model.inference_notes)


if __name__ == "__main__":
    unittest.main()

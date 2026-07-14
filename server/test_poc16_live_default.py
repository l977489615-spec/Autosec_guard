#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import unittest
import sys
from pathlib import Path
from unittest import mock

SERVER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SERVER_DIR))
sys.path.insert(0, str(SERVER_DIR / "pocs"))

POC16_PATH = SERVER_DIR / "pocs" / "network" / "16_Unknown_Protocol_Stateful_Fuzz_Validation.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("poc16_live_test", POC16_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class Poc16LiveDefaultTests(unittest.TestCase):
    def test_defaults_to_live_fuzz_when_not_specified(self):
        module = _load_module()
        plugin = module.UnknownProtocolStatefulFuzzPlugin({
            "target_ip": "192.0.2.10",
            "target_port": 18888,
            "allow_disruptive": True,
            "execution_mode": "full_auto_lab",
            "lab_policy": True,
            "corpus": {
                "target": {"ip": "192.0.2.10", "port": 18888, "transport": "tcp"},
                "sessions": [{
                    "session_id": "S1",
                    "messages": [
                        {"index": 0, "direction": "client_to_server", "timestamp": 1.0, "data_hex": "0100"},
                        {"index": 1, "direction": "server_to_client", "timestamp": 1.1, "data_hex": "8100"},
                    ],
                }],
            },
        })
        captured = {}

        def _fake_campaign(**kwargs):
            captured.update(kwargs)
            return {"cases_executed": 0, "anomalies": [], "manifests": [], "vulnerable": False, "note": "ok"}

        plugin.check_prerequisites()
        with mock.patch.object(module, "run_stateful_fuzz_campaign", side_effect=_fake_campaign):
            plugin.exploit()

        self.assertFalse(captured.get("dry_run"), "protocol fuzz should default to live packets")
        self.assertTrue(captured.get("deposit_dir"))


if __name__ == "__main__":
    unittest.main()

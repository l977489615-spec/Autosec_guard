#!/usr/bin/env python3
from __future__ import annotations

import unittest
import sys
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SERVER_DIR))

from protocol_research.campaign import evaluate_active_fuzz_gates, run_stateful_fuzz_campaign
from protocol_research.corpus import CorpusManager


class StatefulFuzzCampaignTests(unittest.TestCase):
    def test_gates_block_without_lab_policy(self):
        decision = evaluate_active_fuzz_gates(
            service_covered_by_existing_poc=False,
            has_valid_seed_corpus=True,
            execution_mode="full_auto_lab",
            lab_policy=False,
            active_test_approved=True,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.mode, "offline_inference")
        self.assertIn("lab_policy_required", decision.reasons)

    def test_gates_allow_only_when_all_pass(self):
        decision = evaluate_active_fuzz_gates(
            service_covered_by_existing_poc=False,
            has_valid_seed_corpus=True,
            execution_mode="full_auto_lab",
            lab_policy=True,
            active_test_approved=True,
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.mode, "stateful_fuzz")

    def test_dry_run_campaign_never_marks_vulnerable(self):
        manager = CorpusManager()
        doc = manager.create_from_hex_dialog(
            target={"ip": "192.168.10.20", "port": 18888, "transport": "tcp"},
            turns=[
                ("client_to_server", "01000008aabbccdd"),
                ("server_to_client", "8100000400000000"),
                ("client_to_server", "03000004cafebabe"),
                ("server_to_client", "8300000400000002"),
            ],
        )
        gates = evaluate_active_fuzz_gates(
            service_covered_by_existing_poc=False,
            has_valid_seed_corpus=True,
            execution_mode="full_auto_lab",
            lab_policy=True,
            active_test_approved=True,
        )
        result = run_stateful_fuzz_campaign(corpus=doc, gates=gates, dry_run=True, max_cases=8)
        self.assertFalse(result["vulnerable"])
        self.assertEqual(result.get("session_mode"), "stateful_tcp")
        self.assertGreaterEqual(result["cases_executed"], 1)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
from __future__ import annotations

import unittest
import sys
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SERVER_DIR))

from protocol_research.minimizer import minimize_candidate
from protocol_research.models import AnomalyCandidate
from protocol_research.oracles import score_anomaly
from protocol_research.reproducer import reproduce_anomaly
from protocol_research.transport import ExchangeResult, DryRunTransportAdapter


class AnomalyReproductionTests(unittest.TestCase):
    def test_single_timeout_is_not_vulnerability(self):
        baseline = [ExchangeResult(True, "aa", "bb", 1.0, "open")]
        candidate = [ExchangeResult(False, "aa", "", 1.0, "error", error="timeout")]
        verdict = score_anomaly(baseline=baseline, candidate=candidate, health={})
        self.assertFalse(verdict.hits)
        self.assertEqual(verdict.anomaly_score, 0.0)

    def test_service_oracle_reproduces(self):
        transport = DryRunTransportAdapter({"01": "ok", "dead": ""})

        def play(msgs):
            return transport.play_sequence(msgs)

        def health():
            if transport.calls and transport.calls[-1] == "dead":
                return {"process_exited": True}
            return {}

        anomaly = reproduce_anomaly(
            baseline_messages=["01"],
            candidate_messages=["dead"],
            play=play,
            health=health,
            attempts=3,
            required_hits=2,
        )
        self.assertEqual(anomaly.status, "reproduced")
        minimized = minimize_candidate(
            baseline_messages=["01"],
            candidate=anomaly,
            play=play,
            attempts=2,
        )
        self.assertEqual(minimized.status, "minimized")


if __name__ == "__main__":
    unittest.main()

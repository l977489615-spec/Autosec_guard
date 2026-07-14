#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest
import sys
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SERVER_DIR))

from protocol_research.models import AnomalyCandidate
from protocol_research.poc_depositor import PocDepositor


class PocDepositionTests(unittest.TestCase):
    def test_writes_declarative_manifest_not_python(self):
        anomaly = AnomalyCandidate(
            anomaly_id="ANOM-1",
            status="minimized",
            score=0.8,
            oracle_hits=["service_unavailable:process_exited"],
            messages_hex=["0100", "03ffff"],
            evidence={"attempts": 3},
        )
        with tempfile.TemporaryDirectory() as tmp:
            depositor = PocDepositor(tmp)
            manifest = depositor.build_manifest(
                anomaly=anomaly,
                campaign_id="FUZZ-1",
                target_profile={"transport": "tcp", "port": 18888, "service_fingerprint": "sha256:abc"},
                state_path=["S0", "S1", "S2"],
                baseline_probe="0100",
            )
            path = depositor.write_manifest(manifest)
            self.assertTrue(path.exists())
            self.assertEqual(path.suffix, ".json")
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], "1.0")
            self.assertEqual(payload["status"], "candidate_poc")
            self.assertTrue(path.with_suffix(".sha256").exists())
            # must not emit executable python
            self.assertFalse(any(p.suffix == ".py" for p in Path(tmp).iterdir()))


if __name__ == "__main__":
    unittest.main()

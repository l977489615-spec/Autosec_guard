#!/usr/bin/env python3
from __future__ import annotations

import unittest
import sys
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SERVER_DIR))

from agent_orchestrator import AgentOrchestrator


class AgentOrchestratorExecutionModeTests(unittest.TestCase):
    def test_split_execution_passes_safe_then_escalation(self) -> None:
        orch = AgentOrchestrator.__new__(AgentOrchestrator)

        def fake_is_high_risk(name: str):
            if "safe" in name:
                return False, {"risk_level": "SAFE", "domain": "network"}
            if "probe" in name:
                return False, {"risk_level": "PROBE", "domain": "wireless"}
            if "restart" in name:
                return True, {"risk_level": "RESTART", "domain": "network"}
            return True, {"risk_level": "DATALOSS", "domain": "application"}

        orch._is_high_risk_poc = fake_is_high_risk  # type: ignore[attr-defined]
        passes = orch._split_execution_passes([
            {"step": 1, "poc_name": "application/dataloss.py"},
            {"step": 2, "poc_name": "network/restart.py"},
            {"step": 3, "poc_name": "wireless/probe.py"},
            {"step": 4, "poc_name": "network/safe.py"},
        ])
        self.assertEqual([name for name, _items in passes], ["safe-pass", "escalation-pass"])
        self.assertEqual([item["poc_name"] for item in passes[0][1]], ["wireless/probe.py", "network/safe.py"])
        self.assertEqual([item["poc_name"] for item in passes[1][1]], ["network/restart.py", "application/dataloss.py"])


if __name__ == "__main__":
    unittest.main()

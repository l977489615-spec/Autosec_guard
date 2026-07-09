#!/usr/bin/env python3
from __future__ import annotations

import unittest
import sys
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SERVER_DIR))

from agent_orchestrator import AgentOrchestrator


class AgentReflectionReentryTests(unittest.TestCase):
    def test_disabled_reflector_phase_returns_skipped(self) -> None:
        orch = AgentOrchestrator.__new__(AgentOrchestrator)
        orch.enable_reflection_reentry = False
        orch.current_logs = []
        orch.phase_records = []
        orch.findings = []
        orch.manual_review_wait_seconds = 0.0
        orch.structured_results = {"assessment": {}, "llm_usage": {}, "reflector": {}}
        orch._add_log = lambda entry: orch.current_logs.append(entry)  # type: ignore[attr-defined]
        orch._upsert_phase_record = lambda **kwargs: None  # type: ignore[attr-defined]
        orch._refresh_supervisor_metrics = lambda: None  # type: ignore[attr-defined]
        orch._refresh_llm_usage = lambda: None  # type: ignore[attr-defined]
        orch._record_phase = lambda phase, status, raw_output, structured_output, error_message=None: orch.phase_records.append({  # type: ignore[attr-defined]
            "phase": phase,
            "status": status,
            "raw_output": raw_output,
            "structured_output": structured_output,
            "error_message": error_message,
        })

        response = AgentOrchestrator.run_phase(orch, "reflector", context="")

        self.assertFalse(response["enable_reflection_reentry"])
        self.assertEqual(response["structured_result"]["reason"], "reflection_reentry_disabled")
        self.assertEqual(response["phase_records"][-1]["phase"], "reflector")
        self.assertEqual(response["phase_records"][-1]["status"], "skipped")

    def test_resume_from_reflector_redirects_to_assess_when_disabled(self) -> None:
        orch = AgentOrchestrator.__new__(AgentOrchestrator)
        orch.enable_reflection_reentry = False
        orch.target_name = "Target"
        orch.target_ip = "127.0.0.1"
        orch.start_time = 0.0
        orch.current_logs = []
        orch.phase_records = []
        orch.findings = []
        orch.manual_review_wait_seconds = 0.0
        orch.reflector_reentry_count = 0
        orch.reflector_reentry_history = []
        orch.structured_results = {
            "attack_plan": {"items": []},
            "execution": {"items": []},
            "assessment": {},
            "reflector": {},
            "llm_usage": {},
        }
        orch.recon_result = "recon"
        orch.attack_plan = "{}"
        orch.execution_results = "{}"
        orch.final_report = ""
        orch._build_available_params_context = lambda: ""  # type: ignore[attr-defined]
        orch._build_reflector_focus_context = lambda: ""  # type: ignore[attr-defined]
        orch._run_assessment_phase = lambda context="": "final-report"  # type: ignore[attr-defined]
        orch._refresh_supervisor_metrics = lambda: None  # type: ignore[attr-defined]
        orch._refresh_llm_usage = lambda: None  # type: ignore[attr-defined]
        orch._add_log = lambda entry: orch.current_logs.append(entry)  # type: ignore[attr-defined]
        orch._record_phase = lambda phase, status, raw_output, structured_output, error_message=None: orch.phase_records.append({  # type: ignore[attr-defined]
            "phase": phase,
            "status": status,
            "raw_output": raw_output,
            "structured_output": structured_output,
            "error_message": error_message,
        })

        report = AgentOrchestrator.run_from_phase(orch, "reflector")

        self.assertFalse(report["enable_reflection_reentry"])
        self.assertEqual(report["phases"]["assessment_report"], "final-report")
        self.assertEqual(report["phase_records"][0]["phase"], "reflector")
        self.assertEqual(report["phase_records"][0]["status"], "skipped")


if __name__ == "__main__":
    unittest.main()

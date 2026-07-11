#!/usr/bin/env python3
from __future__ import annotations

import unittest
import sys
from pathlib import Path
from unittest import mock

SERVER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SERVER_DIR))

from agent_orchestrator import AgentOrchestrator


class AgentOrchestratorExecutionModeTests(unittest.TestCase):
    def _execution_orchestrator(self, destructive_policy: str, approval_tokens=None):
        orch = AgentOrchestrator.__new__(AgentOrchestrator)
        orch.target_ip = "192.0.2.10"
        orch.candidate_ports = ""
        orch.execution_mode = "PROGRESSIVE_AUTO"
        orch.destructive_policy = destructive_policy
        orch.risk_ceiling = "RESTART"
        orch.allow_domains = []
        orch.lab_policy = False
        orch.batch_approval_token = "batch" if destructive_policy == "ALLOW_ALL" else ""
        orch.approval_tokens = approval_tokens or {}
        orch.available_params = {}
        orch.interactive_review = False
        orch.approve_high_risk_batch = False
        orch.manual_review_wait_seconds = 0.0
        orch.trace_id = "trace"
        orch.executor_agent = mock.Mock(tool_state={})
        orch._add_log = mock.Mock()
        orch._is_high_risk_poc = mock.Mock(return_value=(True, {"risk_level": "RESTART", "domain": "network"}))
        orch._progressive_preflight = mock.Mock(return_value={"risk_level": "RESTART", "preflight_ready": True})
        return orch

    def test_confirm_each_returns_approval_request_without_execution(self):
        orch = self._execution_orchestrator("CONFIRM_EACH")
        with mock.patch("agent_orchestrator.call_mcp_tool") as call:
            result = orch._run_execution_branch(
                {"poc_name": "network/disruptive.py"},
                {"name": "primary", "params": {}, "cooldown_s": 0},
                {},
            )
        self.assertTrue(result["blocked"])
        self.assertTrue(result["requires_approval"])
        self.assertEqual(result["approval_state"], "pending")
        call.assert_not_called()

    def test_deny_all_blocks_without_approval_request(self):
        orch = self._execution_orchestrator("DENY_ALL")
        with mock.patch("agent_orchestrator.call_mcp_tool") as call:
            result = orch._run_execution_branch(
                {"poc_name": "network/disruptive.py"},
                {"name": "primary", "params": {}, "cooldown_s": 0},
                {},
            )
        self.assertTrue(result["blocked"])
        self.assertFalse(result["requires_approval"])
        call.assert_not_called()

    def test_single_approval_executes_only_within_safety_scope(self):
        poc = "network/disruptive.py"
        orch = self._execution_orchestrator("CONFIRM_EACH", {poc: "single-use"})
        with mock.patch("agent_orchestrator.call_mcp_tool", return_value={"success": True, "vulnerable": False}) as call:
            result = orch._run_execution_branch(
                {"poc_name": poc},
                {"name": "primary", "params": {}, "cooldown_s": 0},
                {},
            )
        self.assertTrue(result["success"])
        params = call.call_args.args[1]["params"]
        self.assertEqual(params["approval_token"], "single-use")

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

    def test_truncated_browser_parameters_are_rejected_without_500(self) -> None:
        orch = AgentOrchestrator.__new__(AgentOrchestrator)
        orch._add_log = mock.Mock()
        item = {
            "poc_name": "network/03_CWE_200_SSH_Service_Active_Validation.py",
            "parameters": "[truncated-depth]",
            "strategy": "default",
        }

        branches = orch._build_execution_branches(item, {})

        self.assertEqual(item["parameters"], {})
        self.assertEqual(branches[0]["params"], {})
        orch._add_log.assert_called_once()


if __name__ == "__main__":
    unittest.main()

import unittest
from unittest import mock

from capability_scheduler import CapabilityScheduler
from agent_orchestrator import AgentOrchestrator


DESCRIPTORS = [
    {
        "poc_file": "a.py",
        "grants_on_confirmed": ["capability:a"],
        "required_params": ["target_ip"],
    },
    {
        "poc_file": "b.py",
        "requires_capabilities": ["capability:a"],
        "grants_on_confirmed": ["capability:b"],
        "required_params": ["target_ip"],
        "severity": "High",
    },
    {
        "poc_file": "c.py",
        "requires_capabilities": ["capability:b"],
        "required_params": ["target_ip"],
    },
]


class CapabilitySchedulerTests(unittest.TestCase):
    def setUp(self):
        self.scheduler = CapabilityScheduler(DESCRIPTORS, subject="192.0.2.10")

    def test_confirmed_a_unlocks_b_then_confirmed_b_unlocks_c(self):
        self.assertEqual(self.scheduler.evaluate_delta(), [])
        facts = self.scheduler.observe("a.py", {"vulnerable": True, "verification_status": "auto_confirmed_vulnerable"})
        self.assertEqual([fact.capability for fact in facts], ["capability:a"])
        self.assertEqual([item["poc_file"] for item in self.scheduler.evaluate_delta()], ["b.py"])
        self.scheduler.observe("b.py", {"vulnerable": True, "verification_status": "manual_confirmed_vulnerable"})
        self.assertEqual([item["poc_file"] for item in self.scheduler.evaluate_delta()], ["c.py"])

    def test_execution_success_without_vulnerability_does_not_unlock(self):
        self.scheduler.observe("a.py", {"success": True, "vulnerable": False})
        self.assertEqual(self.scheduler.evaluate_delta(), [])

    def test_pending_manual_review_does_not_unlock(self):
        self.scheduler.observe("a.py", {
            "vulnerable": True,
            "requires_human_review": True,
            "verification_status": "pending_manual_review",
        })
        self.assertEqual(self.scheduler.evaluate_delta(), [])

    def test_facts_are_bound_to_subject_and_survive_hydration(self):
        self.scheduler.observe("a.py", {"vulnerable": True})
        restored = CapabilityScheduler(DESCRIPTORS, subject="192.0.2.10")
        restored.hydrate(self.scheduler.snapshot())
        self.assertEqual([item["poc_file"] for item in restored.evaluate_delta()], ["b.py"])
        other = CapabilityScheduler(DESCRIPTORS, subject="192.0.2.11")
        other.hydrate(self.scheduler.snapshot())
        self.assertEqual(other.evaluate_delta(), [])

    def test_orchestrator_executes_newly_unlocked_incremental_frontier(self):
        orchestrator = AgentOrchestrator.__new__(AgentOrchestrator)
        orchestrator.target_ip = "192.0.2.10"
        orchestrator.available_params = {"target_ip": "192.0.2.10"}
        orchestrator.capability_scheduler = CapabilityScheduler(DESCRIPTORS, subject=orchestrator.target_ip)
        orchestrator.structured_results = {
            "attack_plan": {"items": [{"step": 1, "poc_name": "a.py", "parameters": {"target_ip": "192.0.2.10"}}]},
            "capability_graph": {},
            "supervisor": {"events": [], "metrics": {}, "adjustments": []},
        }
        orchestrator.attack_plan = ""
        orchestrator._record_supervisor_event = mock.Mock()
        orchestrator._execute_plan_stepwise = mock.Mock(side_effect=[
            ("A", {"items": [{"step": 1, "poc_name": "a.py", "status": "vulnerable", "vulnerable": True}]}),
            ("B", {"items": [{"step": 2, "poc_name": "b.py", "status": "completed", "vulnerable": False}]}),
        ])

        _, result = orchestrator._execute_with_capability_expansion()

        self.assertEqual(orchestrator._execute_plan_stepwise.call_count, 2)
        self.assertEqual([item["poc_name"] for item in result["items"]], ["a.py", "b.py"])
        self.assertEqual(
            [item["poc_name"] for item in orchestrator.structured_results["attack_plan"]["items"]],
            ["a.py", "b.py"],
        )


if __name__ == "__main__":
    unittest.main()

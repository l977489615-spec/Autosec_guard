import unittest
from unittest import mock

from agent_orchestrator import (
    AgentOrchestrator,
    DYNAMIC_PROBE_FILENAME,
)


class WeaponizeGenerationPolicyTests(unittest.TestCase):
    def test_execution_boundary_materializes_stale_virtual_token(self):
        orchestrator = AgentOrchestrator.__new__(AgentOrchestrator)
        item = {
            "poc_name": "dynamic_unknown_service_probe",
            "parameters": {"target_port": 1234},
        }

        changed = orchestrator._materialize_dynamic_probe_item(item, "test_guard")

        self.assertTrue(changed)
        self.assertEqual(item["poc_name"], DYNAMIC_PROBE_FILENAME)
        self.assertEqual(item["virtual_poc_name"], "dynamic_unknown_service_probe")
        self.assertEqual(item["parameters"]["probe_profiles"], ["passive_banner"])

    def test_disabled_generator_uses_registered_deterministic_probe(self):
        orchestrator = AgentOrchestrator.__new__(AgentOrchestrator)
        orchestrator.enable_weaponize = False
        orchestrator.structured_results = {
            "attack_plan": {
                "items": [{
                    "poc_name": "dynamic_unknown_service_probe",
                    "status": "pending",
                    "parameters": {"target_port": 1234},
                }]
            }
        }
        orchestrator.attack_plan = ""
        orchestrator.weaponize_agent = mock.Mock()

        result, structured = orchestrator._run_weaponize_generation()

        self.assertIn("已关闭", result)
        self.assertEqual(structured["generation_mode"], "deterministic_template")
        self.assertEqual(
            orchestrator.structured_results["attack_plan"]["items"][0]["poc_name"],
            DYNAMIC_PROBE_FILENAME,
        )
        orchestrator.weaponize_agent.call.assert_not_called()

    def test_model_can_only_select_declarative_profiles_for_existing_port(self):
        orchestrator = AgentOrchestrator.__new__(AgentOrchestrator)
        orchestrator.enable_weaponize = True
        orchestrator.target_ip = "192.0.2.10"
        orchestrator.structured_results = {
            "recon": {"open_ports": [1234], "services": []},
            "attack_plan": {"items": [{
                "poc_name": "dynamic_unknown_service_probe",
                "parameters": {"target_port": 1234},
            }]},
        }
        orchestrator.attack_plan = ""
        orchestrator.weaponize_agent = mock.Mock()
        orchestrator.weaponize_agent.call.return_value = (
            '{"plans":[{"task_index":0,"target_port":1234,'
            '"profiles":["passive_banner","http_head"],"reason":"banner"}]}'
        )

        _, structured = orchestrator._run_weaponize_generation()

        item = orchestrator.structured_results["attack_plan"]["items"][0]
        self.assertEqual(structured["generation_mode"], "llm_declarative_plan")
        self.assertEqual(item["poc_name"], DYNAMIC_PROBE_FILENAME)
        self.assertEqual(item["parameters"]["probe_profiles"], ["passive_banner", "http_head"])

    def test_model_cannot_expand_target_port(self):
        orchestrator = AgentOrchestrator.__new__(AgentOrchestrator)
        orchestrator.enable_weaponize = True
        orchestrator.target_ip = "192.0.2.10"
        orchestrator.current_logs = []
        orchestrator.structured_results = {
            "recon": {"open_ports": [1234], "services": []},
            "attack_plan": {"items": [{
                "poc_name": "dynamic_unknown_service_probe",
                "parameters": {"target_port": 1234},
            }]},
        }
        orchestrator.attack_plan = ""
        orchestrator.weaponize_agent = mock.Mock()
        orchestrator.weaponize_agent.call.return_value = (
            '{"plans":[{"task_index":0,"target_port":65535,'
            '"profiles":["passive_banner"]}]}'
        )
        orchestrator._add_log = mock.Mock()

        _, structured = orchestrator._run_weaponize_generation()

        self.assertEqual(structured["generation_mode"], "deterministic_template")
        item = orchestrator.structured_results["attack_plan"]["items"][0]
        self.assertEqual(item["parameters"]["target_port"], 1234)


if __name__ == "__main__":
    unittest.main()

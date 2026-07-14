import unittest
from unittest import mock

from agent_orchestrator import AgentOrchestrator
from agent_poc_catalog_context import load_runtime_poc_catalog_entries
from capability_scheduler import CapabilityScheduler


USB_POC = "network/01_CWE_489_USB_ADB_Debug_Interface_Active_Validation.py"


class ReflectionReentryGuardTests(unittest.TestCase):
    def test_filtered_out_poc_is_not_recovered_as_executable_item(self):
        orchestrator = AgentOrchestrator.__new__(AgentOrchestrator)
        orchestrator.target_ip = "192.0.2.10"
        orchestrator._canonicalize_poc_reference = mock.Mock(
            side_effect=lambda path: (path, "exact")
        )
        malformed = """
        {"filtered_out": [
          "硬过滤：network/01_CWE_489_USB_ADB_Debug_Interface_Active_Validation.py，缺少 USB"
        ],
        "items": [
          {"poc_name": "network/03_CWE_200_SSH_Service_Active_Validation.py"}
        ],
        "safety_guardrails": ["stop"]
        """

        items = orchestrator._heuristic_extract_plan_items(malformed)

        self.assertEqual(
            [item["poc_name"] for item in items],
            ["network/03_CWE_200_SSH_Service_Active_Validation.py"],
        )

    def test_usb_profile_is_loaded_and_blocked_without_local_usb(self):
        entries = load_runtime_poc_catalog_entries()
        usb_entry = next(item for item in entries if item["poc_file"] == USB_POC)
        self.assertIn("usb_adb", usb_entry["profiles"])

        orchestrator = AgentOrchestrator.__new__(AgentOrchestrator)
        orchestrator.target_ip = "192.0.2.10"
        orchestrator.available_params = {"target_ip": orchestrator.target_ip}
        orchestrator.capability_scheduler = CapabilityScheduler(
            [usb_entry], subject=orchestrator.target_ip
        )

        reason = orchestrator._resource_block_reason_for_plan_item({
            "poc_name": USB_POC,
            "parameters": {"target_ip": orchestrator.target_ip},
        })

        self.assertIn("USB ADB", reason)

    def test_conclusive_result_in_archive_prevents_reentry_rerun(self):
        orchestrator = AgentOrchestrator.__new__(AgentOrchestrator)
        orchestrator.structured_results = {
            "execution": {"items": []},
            "execution_archive": [{
                "items": [{
                    "poc_name": "network/example.py",
                    "status": "vulnerable",
                    "verification_status": "auto_confirmed_vulnerable",
                    "evidence": "protocol response and structured verdict",
                }]
            }],
        }

        self.assertTrue(orchestrator._prior_result_is_conclusive("network/example.py"))

    def test_empty_evidence_remains_eligible_for_targeted_reentry(self):
        orchestrator = AgentOrchestrator.__new__(AgentOrchestrator)
        orchestrator.structured_results = {
            "execution": {"items": []},
            "execution_archive": [{
                "items": [{
                    "poc_name": "network/example.py",
                    "status": "vulnerable",
                    "verification_status": "auto_confirmed_vulnerable",
                    "evidence": "",
                }]
            }],
        }

        self.assertFalse(orchestrator._prior_result_is_conclusive("network/example.py"))


if __name__ == "__main__":
    unittest.main()

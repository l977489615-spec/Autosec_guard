import unittest

from poc_catalog import resolve_poc_source
from poc_security import extract_poc_security_profile
from poc_worker import apply_manual_review_state, poc_requires_human_review


class PocManualReviewPolicyTests(unittest.TestCase):
    def _profile(self, poc_file: str):
        path, normalized, source = resolve_poc_source("pocs", poc_file)
        self.assertIsNotNone(path)
        return normalized, extract_poc_security_profile(path, source_text=source)

    def test_ssh_service_auto_confirms_without_manual_review(self):
        poc_file, profile = self._profile("network/03_CWE_200_SSH_Service_Active_Validation.py")
        self.assertFalse(poc_requires_human_review(poc_file, profile))
        result = apply_manual_review_state(
            {"success": True, "vulnerable": True, "evidence": "SSH banner: SSH-2.0-OpenSSH"},
            poc_filename=poc_file,
            security_profile=profile,
            plugin_results={},
        )
        self.assertFalse(result["requires_human_review"])
        self.assertEqual(result["verification_status"], "auto_confirmed_vulnerable")

    def test_telnet_weak_creds_auto_confirms_on_login_evidence(self):
        poc_file, profile = self._profile("network/07_CWE_521_Telnet_Weak_Credentials_Active_Validation.py")
        plugin_results = {"vulnerable": True, "evidence": "Telnet login successful with root:123456"}
        self.assertFalse(poc_requires_human_review(poc_file, profile, plugin_results))
        result = apply_manual_review_state(
            {"success": True, "vulnerable": True, "evidence": plugin_results["evidence"]},
            poc_filename=poc_file,
            security_profile=profile,
            plugin_results=plugin_results,
        )
        self.assertFalse(result["requires_human_review"])

    def test_can_replay_still_requires_manual_review(self):
        poc_file, profile = self._profile("canbus/04_CWE_294_CAN_Replay_Attack_Active_Validation.py")
        self.assertTrue(poc_requires_human_review(poc_file, profile))

    def test_keyfob_replay_still_requires_manual_review(self):
        poc_file, profile = self._profile("advanced/02_CVE_2022_27254_RF_Keyfob_Replay_Active_Validation.py")
        self.assertTrue(poc_requires_human_review(poc_file, profile))

    def test_plugin_flag_cannot_force_network_poc_into_physical_review(self):
        poc_file, profile = self._profile("network/03_CWE_200_SSH_Service_Active_Validation.py")
        self.assertFalse(
            poc_requires_human_review(
                poc_file,
                profile,
                plugin_results={"requires_manual_review": True},
            )
        )
        self.assertFalse(
            poc_requires_human_review(
                poc_file,
                profile,
                plugin_results={"requires_manual_review": False},
            )
        )

    def test_rtsp_log_leak_does_not_request_physical_review(self):
        poc_file, profile = self._profile("network/11_CWE_200_RTSP_Log_Leak_Active_Validation.py")
        result = apply_manual_review_state(
            {"success": True, "vulnerable": True, "evidence": "log leak"},
            poc_filename=poc_file,
            security_profile=profile,
            plugin_results={"requires_human_review": True},
        )
        self.assertFalse(result["requires_human_review"])
        self.assertEqual(result["verification_status"], "auto_confirmed_vulnerable")

    def test_negative_verdict_keeps_evidence(self):
        poc_file, profile = self._profile("network/03_CWE_200_SSH_Service_Active_Validation.py")
        result = apply_manual_review_state(
            {"success": True, "vulnerable": False, "evidence": "SSH port closed with TCP RST"},
            poc_filename=poc_file,
            security_profile=profile,
            plugin_results={},
        )
        self.assertEqual(result["verification_status"], "auto_confirmed_not_vulnerable")
        self.assertEqual(result["evidence"], "SSH port closed with TCP RST")
        self.assertTrue(result["evidence_contract_valid"])

    def test_empty_evidence_cannot_produce_confirmed_verdict(self):
        poc_file, profile = self._profile("network/03_CWE_200_SSH_Service_Active_Validation.py")
        result = apply_manual_review_state(
            {"success": True, "vulnerable": False, "evidence": ""},
            poc_filename=poc_file,
            security_profile=profile,
            plugin_results={},
        )
        self.assertEqual(result["verification_status"], "invalid_result")
        self.assertIsNone(result["vulnerable"])
        self.assertFalse(result["evidence_contract_valid"])


if __name__ == "__main__":
    unittest.main()

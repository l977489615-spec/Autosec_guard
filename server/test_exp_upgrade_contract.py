#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import textwrap
import sys
import unittest
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SERVER_DIR))
sys.path.insert(0, str(SERVER_DIR / "pocs"))

from audit_exp_readiness import PROFESSIONAL_TIER_ORDER, audit_file
from scan_cli import _tier_allowed
import pocs.active_validation_core as active_core
from pocs.active_validation_core import run_active_validation
from pocs.iv_plugin_base import IVIVulnerabilityPlugin


POCS_DIR = SERVER_DIR / "pocs"


class ExpReadinessContractTests(unittest.TestCase):
    def test_shared_lab_harness_counts_as_exp_ready(self) -> None:
        source = textwrap.dedent(
            '''
            from active_validation_core import run_active_validation
            from iv_plugin_base import IVIVulnerabilityPlugin

            VULN = {
                "cve": "CVE-2099-0001",
                "summary": "lab trigger contract",
                "exp_profile": "operator_supplied_lab_payload",
                "active_payload_param": "lab_payload_hex",
                "operator_observation": "target-side crash or state change",
            }

            class DemoCertificateValidationAuditPlugin(IVIVulnerabilityPlugin):
                meta_poc_name = "Demo Certificate Validation Audit"
                meta_cve_id = "CVE-2099-0001"
                meta_protocol = "local"
                is_disruptive = True
                meta_destructive_level = "Disruptive"

                def check_prerequisites(self):
                    return True

                def exploit(self):
                    return run_active_validation(self, VULN)
            '''
        )
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix="_Certificate_Validation_Audit.py",
            dir=POCS_DIR,
            delete=False,
        ) as handle:
            handle.write(source)
            path = Path(handle.name)
        try:
            finding = audit_file(path)
        finally:
            path.unlink(missing_ok=True)

        self.assertIsNotNone(finding)
        self.assertEqual(finding.grade, "EXP_READY")
        self.assertEqual(finding.missing, [])
        self.assertEqual(finding.validation_tier, "LAB_EXP")
        self.assertEqual(finding.exp_capability, "operator_supplied")
        self.assertEqual(finding.execution_safety, "destructive_lab_only")
        self.assertIn("operator_payload", finding.evidence_basis)

    def test_legacy_plugin_inherits_generic_exp_harness(self) -> None:
        source = textwrap.dedent(
            '''
            from iv_plugin_base import IVIVulnerabilityPlugin

            class LegacyStaticAuditPlugin(IVIVulnerabilityPlugin):
                meta_poc_name = "Legacy Static Audit"
                meta_cve_id = "CWE-22"
                meta_protocol = "local"

                def check_prerequisites(self):
                    return True

                def exploit(self):
                    return {"vulnerable": False, "evidence": "static metadata only"}
            '''
        )
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix="_Legacy_Audit.py",
            dir=POCS_DIR,
            delete=False,
        ) as handle:
            handle.write(source)
            path = Path(handle.name)
        try:
            finding = audit_file(path)
        finally:
            path.unlink(missing_ok=True)

        self.assertIsNotNone(finding)
        self.assertEqual(finding.grade, "EXP_READY")
        self.assertEqual(finding.missing, [])
        self.assertEqual(finding.validation_tier, "PASSIVE")
        self.assertEqual(finding.exp_capability, "supported_harness")
        self.assertTrue(finding.not_native_exp)

    def test_native_active_script_is_auto_exp_verified(self) -> None:
        source = textwrap.dedent(
            '''
            import socket
            from iv_plugin_base import IVIVulnerabilityPlugin

            class NativeExploitPlugin(IVIVulnerabilityPlugin):
                meta_poc_name = "Native EXP"
                meta_cve_id = "CVE-2099-0100"
                meta_protocol = "tcp"
                is_disruptive = True
                meta_destructive_level = "Disruptive"

                def check_prerequisites(self):
                    return True

                def exploit(self):
                    payload = b"malformed overflow payload"
                    with socket.create_connection((self.target_ip, int(self.target_port)), timeout=1) as sock:
                        sock.sendall(payload)
                    return {
                        "vulnerable": True,
                        "evidence": "before/after reset observed; crash confirmed",
                    }
            '''
        )
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix="_Native_EXP.py",
            dir=POCS_DIR,
            delete=False,
        ) as handle:
            handle.write(source)
            path = Path(handle.name)
        try:
            finding = audit_file(path)
        finally:
            path.unlink(missing_ok=True)

        self.assertIsNotNone(finding)
        self.assertEqual(finding.validation_tier, "AUTO_EXP")
        self.assertEqual(finding.exp_capability, "native_verified")
        self.assertFalse(finding.not_native_exp)

    def test_real_version_audit_is_safe_professional_tier(self) -> None:
        finding = audit_file(POCS_DIR / "application/29_CVE_2016_6309_OpenSSL_Version_Active_Validation.py")

        self.assertIsNotNone(finding)
        self.assertIn(finding.validation_tier, {"PASSIVE", "AUTHENTICATED_CONFIG"})
        self.assertNotEqual(finding.exp_capability, "native_verified")

    def test_real_local_decoder_probe_is_lab_harness_not_remote_active(self) -> None:
        finding = audit_file(POCS_DIR / "application/64_CVE_2023_4863_Active_Validation.py")

        self.assertIsNotNone(finding)
        self.assertEqual(finding.validation_tier, "LAB_EXP")
        self.assertNotEqual(finding.exp_capability, "native_verified")


class ActiveValidationContractTests(unittest.TestCase):
    def test_operator_supplied_payload_requires_authorization(self) -> None:
        class DemoPlugin:
            params = {"validation_mode": "probe", "software_inventory_text": "CVE-2099-0002"}
            meta_protocol = "local"

        vuln = {
            "cve": "CVE-2099-0002",
            "summary": "operator supplied lab trigger",
            "signature_tokens": ["CVE-2099-0002"],
            "active_payload_param": "lab_payload_hex",
            "exp_profile": "operator_supplied_lab_payload",
        }

        result = run_active_validation(DemoPlugin(), vuln)
        evidence = json.loads(result["evidence"])
        trigger = next(item for item in evidence["active_observations"] if item["kind"] == "authorized_trigger")

        self.assertTrue(trigger["requires_manual_review"])
        self.assertTrue(trigger["payload_supported"])
        self.assertFalse(trigger["payload_available"])
        self.assertEqual(trigger["payload_source"], "operator_parameter_required")
        self.assertIn("allow_disruptive=true", trigger["reason"])
        self.assertNotEqual(evidence["validation_tier_achieved"], "LAB_EXP")
        self.assertEqual(evidence["exp_capability"], "operator_supplied")

    def test_passive_validation_merges_without_exception(self) -> None:
        class DemoPlugin:
            params = {"validation_mode": "passive", "software_inventory_text": "CVE-2099-0006 demo"}
            meta_protocol = "local"

        result = run_active_validation(
            DemoPlugin(),
            {"cve": "CVE-2099-0006", "summary": "passive merge", "signature_tokens": ["CVE-2099-0006"]},
        )
        evidence = json.loads(result["evidence"])

        self.assertEqual(evidence["validation_mode"], "passive")
        self.assertEqual(evidence["active_validation"], "disabled_by_request")
        self.assertTrue(evidence["exposure_detected"])
        self.assertFalse(evidence["active_probe_observed"])
        self.assertFalse(evidence["exploit_trigger_supported"])
        self.assertIsNone(evidence["exploit_confirmed"])

    def test_payload_is_not_sent_without_disruptive_authorization(self) -> None:
        class DemoPlugin:
            params = {
                "validation_mode": "probe",
                "target_ip": "127.0.0.1",
                "target_port": 9999,
                "active_payload_text": "PING\r\n",
            }
            meta_protocol = "tcp"

        calls = []
        original = active_core._send_tcp

        def fake_send(*args, **kwargs):
            calls.append((args, kwargs))
            return b"+PONG\r\n"

        active_core._send_tcp = fake_send
        try:
            result = run_active_validation(DemoPlugin(), {"cve": "CVE-2099-0004", "summary": "tcp trigger"})
        finally:
            active_core._send_tcp = original

        evidence = json.loads(result["evidence"])
        trigger = next(item for item in evidence["active_observations"] if item["kind"] == "authorized_trigger")
        self.assertEqual(calls, [])
        self.assertFalse(trigger["ok"])
        self.assertTrue(trigger["payload_available"])
        self.assertIn("allow_disruptive=true", trigger["reason"])

    def test_declared_generic_payload_param_is_treated_as_text(self) -> None:
        class DemoPlugin:
            params = {
                "validation_mode": "probe",
                "target_ip": "127.0.0.1",
                "target_port": 9999,
                "allow_disruptive": True,
                "lab_payload": "PING\r\n",
            }
            meta_protocol = "tcp"

        sent_payloads = []
        original_send = active_core._send_tcp
        original_liveness = active_core._tcp_liveness

        def fake_send(host, port, payload, **kwargs):
            sent_payloads.append(payload)
            return b"+PONG\r\n"

        def fake_liveness(host, port, params):
            return {"kind": "tcp_liveness", "ok": True}

        active_core._send_tcp = fake_send
        active_core._tcp_liveness = fake_liveness
        try:
            run_active_validation(
                DemoPlugin(),
                {"cve": "CVE-2099-0005", "summary": "tcp text trigger", "active_payload_param": "lab_payload"},
            )
        finally:
            active_core._send_tcp = original_send
            active_core._tcp_liveness = original_liveness

        self.assertEqual(sent_payloads, [b"PING\r\n"])


class GenericHarnessContractTests(unittest.TestCase):
    def test_prerequisite_failure_still_records_generic_harness(self) -> None:
        class DemoPlugin(IVIVulnerabilityPlugin):
            meta_protocol = "rf"
            meta_cve_id = "CWE-345"

            def check_prerequisites(self):
                return False

            def exploit(self):
                return {"vulnerable": False}

        plugin = DemoPlugin({"generic_exp_payload_text": "rf_lab_payload"})
        plugin.run_verify()
        evidence = json.loads(plugin.results["evidence"])

        self.assertIn("exp_harness", evidence)
        self.assertTrue(evidence["exp_harness"][0]["payload_available"])
        self.assertEqual(evidence["exp_harness"][0]["harness_tier"], "LAB_EXP")
        self.assertNotEqual(evidence["exp_harness"][0]["validation_tier_achieved"], "LAB_EXP")

    def test_non_network_trigger_reports_lab_execution_requirement(self) -> None:
        class DemoPlugin:
            params = {"validation_mode": "probe", "allow_disruptive": True, "can_frame": "123#DEADBEEF"}
            meta_protocol = "can"

        vuln = {
            "cve": "CVE-2099-0003",
            "summary": "CAN lab trigger",
            "active_payload_param": "can_frame",
            "exp_profile": "can_bus_lab_trigger",
        }

        result = run_active_validation(DemoPlugin(), vuln)
        evidence = json.loads(result["evidence"])
        trigger = next(item for item in evidence["active_observations"] if item["kind"] == "authorized_trigger")

        self.assertTrue(trigger["requires_manual_review"])
        self.assertEqual(trigger["protocol"], "can")
        self.assertIn("operator_action", trigger)
        self.assertIn("can_frame", trigger["payload_parameter"])


class ProfessionalCliPolicyTests(unittest.TestCase):
    def test_tier_filter_allows_safe_default_surface(self) -> None:
        self.assertLess(
            PROFESSIONAL_TIER_ORDER["ACTIVE_PROBE"],
            PROFESSIONAL_TIER_ORDER["LAB_EXP"],
        )
        self.assertTrue(_tier_allowed("ACTIVE_PROBE", "", "ACTIVE_PROBE", False, False))
        self.assertFalse(_tier_allowed("LAB_EXP", "", "ACTIVE_PROBE", False, False))
        self.assertTrue(_tier_allowed("LAB_EXP", "", "ACTIVE_PROBE", True, False))
        self.assertFalse(_tier_allowed("AUTO_EXP", "", "LAB_EXP", True, False))
        self.assertTrue(_tier_allowed("AUTO_EXP", "", "LAB_EXP", True, True))


if __name__ == "__main__":
    unittest.main()

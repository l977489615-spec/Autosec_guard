#!/usr/bin/env python3
from __future__ import annotations

import time
import unittest
import sys
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SERVER_DIR))

from agent_execution_policy import (
    allow_automatic_escalation,
    default_risk_ceiling,
    issue_signed_scope_token,
    normalize_execution_mode,
    preflight_profile,
    risk_level_from_profile,
    verify_signed_scope_token,
)


class AgentExecutionPolicyTests(unittest.TestCase):
    def test_legacy_batch_flag_maps_to_progressive_auto(self) -> None:
        self.assertEqual(normalize_execution_mode("", approve_high_risk_batch=False), "SAFE_ONLY")
        self.assertEqual(normalize_execution_mode("", approve_high_risk_batch=True), "PROGRESSIVE_AUTO")
        self.assertEqual(normalize_execution_mode("full_auto_lab"), "FULL_AUTO_LAB")

    def test_default_risk_ceiling_matches_mode(self) -> None:
        self.assertEqual(default_risk_ceiling("safe_only"), "PROBE")
        self.assertEqual(default_risk_ceiling("progressive_auto"), "RESTART")
        self.assertEqual(default_risk_ceiling("full_auto_lab"), "DATALOSS")

    def test_progressive_auto_allows_restart_but_not_dataloss(self) -> None:
        ok, reason = allow_automatic_escalation(
            execution_mode="progressive_auto",
            risk_level="RESTART",
            risk_ceiling="RESTART",
            preflight_ready=True,
            lab_policy=False,
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "auto-escalation-allowed")

        ok, reason = allow_automatic_escalation(
            execution_mode="progressive_auto",
            risk_level="DATALOSS",
            risk_ceiling="DATALOSS",
            preflight_ready=True,
            lab_policy=False,
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "lab-policy-required")

    def test_brick_is_never_auto_allowed(self) -> None:
        ok, reason = allow_automatic_escalation(
            execution_mode="full_auto_lab",
            risk_level="BRICK",
            risk_ceiling="BRICK",
            preflight_ready=True,
            lab_policy=True,
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "brick-blocked")

    def test_preflight_requires_params_and_domain(self) -> None:
        profile = {
            "required_params": ["target_ip", "bluetooth_mac"],
            "protocol": "bluetooth",
            "destructive_level": "Restart",
        }
        preflight = preflight_profile(
            profile=profile,
            params={"target_ip": "192.168.0.10"},
            domain="wireless",
            target_in_scope=True,
            lab_policy=False,
            allowed_domains=["network"],
        )
        self.assertEqual(risk_level_from_profile(profile), "RESTART")
        self.assertFalse(preflight["preflight_ready"])
        self.assertIn("bluetooth_mac", preflight["missing_required_params"])
        self.assertFalse(preflight["domain_authorized"])

    def test_signed_scope_token_verification_checks_scope_and_ttl(self) -> None:
        secret = "unit-test-secret"
        token = issue_signed_scope_token(secret, {
            "target": "192.168.0.10",
            "session_id": "session-1",
            "risk_ceiling": "RESTART",
            "issued_at": int(time.time()),
        })
        ok, payload, reason = verify_signed_scope_token(
            secret,
            token,
            ttl_seconds=30,
            expected_pairs={"target": "192.168.0.10", "session_id": "session-1"},
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "ok")
        self.assertEqual(payload["risk_ceiling"], "RESTART")

        ok, _payload, reason = verify_signed_scope_token(
            secret,
            token,
            ttl_seconds=30,
            expected_pairs={"target": "192.168.0.99", "session_id": "session-1"},
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "mismatch:target")

        expired = issue_signed_scope_token(secret, {
            "target": "192.168.0.10",
            "session_id": "session-1",
            "risk_ceiling": "RESTART",
            "issued_at": int(time.time()) - 120,
        })
        ok, _payload, reason = verify_signed_scope_token(
            secret,
            expired,
            ttl_seconds=30,
            expected_pairs={"target": "192.168.0.10", "session_id": "session-1"},
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "expired")


if __name__ == "__main__":
    unittest.main()

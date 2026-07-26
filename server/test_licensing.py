import base64
import argparse
import datetime as dt
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent))

import licensing
from license_cli import issue
from licensing import LicenseManager, canonical_payload, format_utc


UTC = dt.timezone.utc


class OfflineLicensingTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)
        self.private_key = Ed25519PrivateKey.generate()
        public_raw = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.public_b64 = base64.b64encode(public_raw).decode("ascii")
        self.now = [dt.datetime(2026, 7, 26, 8, 0, tzinfo=UTC)]
        self.manager = LicenseManager(
            self.data_dir,
            public_key_b64=self.public_b64,
            enforced=True,
            now_provider=lambda: self.now[0],
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def document(self, **overrides):
        payload = {
            "schema": 1,
            "license_id": "LIC-TEST-001",
            "customer": "Test Customer",
            "product": "autosec-guard-edge",
            "edition": "enterprise",
            "issued_at": format_utc(self.now[0]),
            "not_before": format_utc(self.now[0] - dt.timedelta(minutes=1)),
            "expires_at": format_utc(self.now[0] + dt.timedelta(days=31)),
            "machine_code": self.manager.machine_code,
            "features": ["scan", "poc_execution", "report_export"],
            "key_id": "test-key",
        }
        payload.update(overrides)
        signature = self.private_key.sign(canonical_payload(payload))
        return {
            "payload": payload,
            "signature": base64.b64encode(signature).decode("ascii"),
        }

    def test_missing_license_is_restricted(self):
        status = self.manager.evaluate()
        self.assertFalse(status["valid"])
        self.assertEqual(status["state"], "missing")
        self.assertTrue(status["machine_code"])

    def test_valid_license_installs_and_enables_features(self):
        installed = self.manager.install(self.document())
        self.assertTrue(installed["valid"])
        self.assertEqual(installed["state"], "valid")
        self.assertTrue(self.manager.license_path.exists())
        allowed, status = self.manager.feature_allowed("poc_execution")
        self.assertTrue(allowed)
        self.assertGreaterEqual(status["remaining_days"], 30)

    def test_modified_payload_fails_signature_verification(self):
        document = self.document()
        document["payload"]["expires_at"] = "2036-01-01T00:00:00Z"
        status = self.manager.evaluate(document)
        self.assertFalse(status["valid"])
        self.assertEqual(status["state"], "invalid_signature")

    def test_license_for_another_machine_is_rejected(self):
        status = self.manager.evaluate(self.document(machine_code="A" * 64))
        self.assertFalse(status["valid"])
        self.assertEqual(status["state"], "wrong_device")

    def test_expired_license_is_rejected(self):
        status = self.manager.evaluate(self.document(
            not_before="2026-06-01T00:00:00Z",
            expires_at="2026-07-01T00:00:00Z",
        ))
        self.assertFalse(status["valid"])
        self.assertEqual(status["state"], "expired")

    def test_clock_rollback_is_detected(self):
        document = self.document(expires_at="2027-01-01T00:00:00Z")
        self.assertTrue(self.manager.install(document)["valid"])
        self.now[0] += dt.timedelta(days=2)
        self.assertTrue(self.manager.evaluate()["valid"])
        self.now[0] -= dt.timedelta(days=1)
        status = self.manager.evaluate()
        self.assertFalse(status["valid"])
        self.assertEqual(status["state"], "clock_rollback")

    def test_source_development_mode_does_not_need_a_license(self):
        manager = LicenseManager(self.data_dir, public_key_b64="", enforced=False)
        status = manager.evaluate()
        self.assertTrue(status["valid"])
        self.assertEqual(status["state"], "development")

    def test_nuitka_compiled_build_always_enforces_licensing(self):
        with mock.patch.dict(licensing.__dict__, {"__compiled__": object()}), mock.patch.dict(
            "os.environ", {"AUTOSEC_LICENSE_ENFORCEMENT": "off"}, clear=False
        ):
            self.assertTrue(licensing.licensing_enforced())

    def test_vendor_gui_can_issue_without_exporting_password_to_environment(self):
        password = b"test-encrypted-key-password"
        private_path = self.data_dir / "issuer.pem"
        private_path.write_bytes(self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password),
        ))
        output = self.data_dir / "customer.autosec"
        args = argparse.Namespace(
            private_key=private_path,
            customer="Test Customer",
            machine_code=self.manager.machine_code,
            months=3,
            days=None,
            expires_at=None,
            not_before=None,
            license_id="LIC-GUI-TEST",
            edition="enterprise",
            features="scan,poc_execution,report_export",
            key_id="test-key",
            output=output,
        )
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertEqual(issue(args, password=password), 0)
        document = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(document["payload"]["license_id"], "LIC-GUI-TEST")
        self.assertTrue(self.manager.evaluate(document)["valid"])


if __name__ == "__main__":
    unittest.main()

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from poc_worker import (
    LocalSandboxPocWorker,
    _build_sandbox_env,
    _packaged_builtin_name,
    _sanitize_sandbox_params,
)


class SandboxHardeningTests(unittest.TestCase):
    def test_server_secrets_are_not_inherited(self):
        with mock.patch.dict(os.environ, {
            "AUTOSEC_SECRET_KEY": "server-session-secret",
            "DASHSCOPE_API_KEY": "provider-secret",
            "AUTOSEC_LICENSE_ISSUER_PASSWORD": "issuer-secret",
            "PATH": "/usr/bin",
        }, clear=True):
            child_env = _build_sandbox_env({}, ["127.0.0.1"])

        self.assertEqual(child_env["PATH"], "/usr/bin")
        self.assertEqual(child_env["SANDBOX_ALLOWED_HOSTS"], "127.0.0.1")
        self.assertNotIn("AUTOSEC_SECRET_KEY", child_env)
        self.assertNotIn("DASHSCOPE_API_KEY", child_env)
        self.assertNotIn("AUTOSEC_LICENSE_ISSUER_PASSWORD", child_env)

    def test_client_cannot_override_sandbox_policy_or_environment(self):
        clean = _sanitize_sandbox_params({
            "target_ip": "127.0.0.1",
            "sandbox_memory_mb": 999999,
            "sandbox_timeout_seconds": 999999,
            "AUTOSEC_SECRET_KEY": "attacker-value",
        })
        self.assertEqual(clean["target_ip"], "127.0.0.1")
        self.assertNotIn("sandbox_memory_mb", clean)
        self.assertNotIn("sandbox_timeout_seconds", clean)
        self.assertNotIn("AUTOSEC_SECRET_KEY", clean)

    def test_packaged_child_receives_license_context_but_not_application_secrets(self):
        with mock.patch("poc_worker._is_packaged_runtime", return_value=True), \
             mock.patch("poc_worker.get_runtime_data_dir", return_value=Path("/customer/data")), \
             mock.patch.dict(os.environ, {
                 "AUTOSEC_LICENSE_PATH": "/customer/license.autosec",
                 "AUTOSEC_AI_CONFIG_KEY": "customer-ai-encryption-key",
                 "AUTOSEC_SECRET_KEY": "customer-session-key",
             }, clear=True):
            child_env = _build_sandbox_env({}, ["127.0.0.1"])

        self.assertEqual(child_env["AUTOSEC_DATA_DIR"], "/customer/data")
        self.assertEqual(child_env["AUTOSEC_LICENSE_PATH"], "/customer/license.autosec")
        self.assertNotIn("AUTOSEC_AI_CONFIG_KEY", child_env)
        self.assertNotIn("AUTOSEC_SECRET_KEY", child_env)

    def test_packaged_poc_must_exist_in_compiled_catalog(self):
        path = "/private/tmp/onefile/pocs/network/safe_probe.py"
        with mock.patch("poc_worker.get_poc_code", return_value=("print('safe')", "network/safe_probe.py")):
            self.assertEqual(_packaged_builtin_name(path), "network/safe_probe.py")
        with mock.patch("poc_worker.get_poc_code", return_value=(None, None)):
            with self.assertRaisesRegex(ValueError, "compiled catalog"):
                _packaged_builtin_name(path)

    def test_fixture_paths_are_confined_to_runtime_fixture_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp)
            fixtures = runtime / "fixtures"
            fixtures.mkdir()
            allowed = fixtures / "sample.log"
            allowed.write_text("safe", encoding="utf-8")
            outside = runtime / "secret.txt"
            outside.write_text("secret", encoding="utf-8")

            with mock.patch.dict(os.environ, {"AUTOSEC_DATA_DIR": tmp}):
                clean = _sanitize_sandbox_params({"log_fixture": "sample.log"})
                self.assertEqual(clean["log_fixture"], str(allowed.resolve()))
                with self.assertRaises(ValueError):
                    _sanitize_sandbox_params({"log_fixture": str(outside)})

    def test_prepare_clamps_timeout_to_server_ceiling(self):
        worker = LocalSandboxPocWorker()
        with tempfile.TemporaryDirectory() as tmp, mock.patch("poc_worker._extract_security_profile", return_value={}):
            poc_path = str(Path(tmp) / "example.py")
            plan = worker.prepare(
                poc_path,
                {"target_ip": "127.0.0.1", "sandbox_timeout_seconds": 99999},
                trace_id="trace",
                session_id="session",
                timeout_seconds=99999,
            )
        self.assertEqual(plan.timeout_seconds, 300)
        self.assertNotIn("sandbox_timeout_seconds", plan.params)

    def test_sensitive_params_are_not_exposed_in_process_arguments(self):
        worker = LocalSandboxPocWorker()
        with tempfile.TemporaryDirectory() as tmp, mock.patch("poc_worker._extract_security_profile", return_value={}):
            poc_path = str(Path(tmp) / "example.py")
            plan = worker.prepare(
                poc_path,
                {"target_ip": "127.0.0.1", "ssh_password": "do-not-show-in-ps"},
                trace_id="trace",
                session_id="session",
            )
        self.assertNotIn("do-not-show-in-ps", " ".join(plan.command))
        self.assertEqual(plan.params["ssh_password"], "do-not-show-in-ps")

    def test_packaged_runtime_disables_disruptive_host_exploits_by_default(self):
        worker = LocalSandboxPocWorker()
        with mock.patch("poc_worker._is_packaged_runtime", return_value=True), \
             mock.patch("poc_worker._extract_security_profile", return_value={"is_disruptive": True}), \
             mock.patch.dict(os.environ, {"AUTOSEC_ENABLE_HOST_EXPLOITS": "false"}, clear=False):
            with self.assertRaisesRegex(PermissionError, "disabled in customer packages"):
                worker.prepare(
                    "embedded-disruptive.py",
                    {"target_ip": "127.0.0.1"},
                    trace_id="trace",
                    session_id="session",
                )


if __name__ == "__main__":
    unittest.main()

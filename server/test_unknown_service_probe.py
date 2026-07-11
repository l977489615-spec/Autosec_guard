import importlib.util
import json
import socket
import sys
import unittest
from pathlib import Path
from unittest import mock


PATH = Path(__file__).parent / "pocs/network/15_CWE_200_Service_Probe_Active_Validation.py"
sys.path.insert(0, str(PATH.parents[1]))
SPEC = importlib.util.spec_from_file_location("unknown_service_probe", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)
Probe = MODULE.DynamicUnknownServiceProbePlugin


class UnknownServiceProbeTests(unittest.TestCase):
    def test_requires_one_explicit_port(self):
        probe = Probe({"target_ip": "192.0.2.1"})
        with self.assertRaisesRegex(RuntimeError, "target_port"):
            probe.check_prerequisites()

    def test_rejects_unknown_profile(self):
        probe = Probe({
            "target_ip": "192.0.2.1", "target_port": 1234,
            "probe_profiles": ["random_mutation_fuzz"],
        })
        with self.assertRaisesRegex(RuntimeError, "non-allowlisted"):
            probe.check_prerequisites()

    def test_fingerprint_never_claims_vulnerability(self):
        probe = Probe({
            "target_ip": "192.0.2.1", "target_port": 1234,
            "probe_profiles": ["passive_banner"],
        })
        probe.check_prerequisites()
        probe._passive_banner = mock.Mock(return_value={
            "profile": "passive_banner", "received_bytes": 5,
            "preview": "hello", "response_sha256": "hash", "protocol_match": None,
        })

        result = probe.exploit()

        self.assertFalse(result["vulnerable"])
        evidence = json.loads(result["evidence"])
        self.assertEqual(evidence["evidence_type"], "service_fingerprint")
        self.assertIn("no vulnerability conclusion", evidence["conclusion"])


if __name__ == "__main__":
    unittest.main()

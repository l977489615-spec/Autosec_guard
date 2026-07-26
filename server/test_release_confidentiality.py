import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packaging"))

from build_edge_workstation import _verify_release_boundary, build
from security_release_gate import FORBIDDEN_SOURCE


class ReleaseConfidentialityTests(unittest.TestCase):
    def test_security_gate_does_not_match_its_own_rule_definitions(self):
        gate_source = (ROOT / "packaging" / "security_release_gate.py").read_bytes()
        matches = [
            label for label, pattern in FORBIDDEN_SOURCE.items()
            if pattern.search(gate_source)
        ]
        self.assertEqual(matches, [])

    def test_security_gate_still_rejects_disabled_ssh_host_key_checking(self):
        insecure_source = (
            b'args = ["ssh", "-o", "StrictHostKeyChecking' + b'=no"]'
        )
        pattern = FORBIDDEN_SOURCE["disabled SSH host-key checking"]
        self.assertIsNotNone(pattern.search(insecure_source))

    def test_clean_binary_release_boundary_passes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "autosec-guard-edge").write_bytes(b"compiled-binary")
            (root / "assets").mkdir()
            (root / "assets" / "app.js").write_text("(()=>{})();", encoding="utf-8")
            _verify_release_boundary(root)

    def test_source_map_and_private_key_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app.js.map").write_text("{}", encoding="utf-8")
            (root / "issuer.pem").write_bytes(
                b"-----BEGIN " + b"PRIVATE KEY-----\nnot-a-real-key\n"
            )
            with self.assertRaisesRegex(RuntimeError, "source/debug artifact"):
                _verify_release_boundary(root)

    def test_pyinstaller_customer_build_is_rejected_before_building(self):
        with self.assertRaisesRegex(RuntimeError, "PyInstaller fallback is prohibited"):
            build("pyinstaller")


if __name__ == "__main__":
    unittest.main()

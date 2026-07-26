import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packaging"))

from build_edge_workstation import _verify_release_boundary, build


class ReleaseConfidentialityTests(unittest.TestCase):
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

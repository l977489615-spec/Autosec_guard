import unittest
from pathlib import Path

from agent_poc_catalog_context import build_decision_poc_context, load_poc_catalog_entries
from poc_catalog import resolve_poc_path

POCS_DIR = str(Path(__file__).resolve().parent / "pocs")


class RuntimePocCatalogTests(unittest.TestCase):
    def test_runtime_catalog_does_not_require_lab(self):
        entries = load_poc_catalog_entries(coverage_path="/nonexistent/lab/evidence/poc_coverage.json")
        self.assertGreaterEqual(len(entries), 318)
        for item in entries[:5]:
            poc_file = item.get("poc_file")
            self.assertTrue(poc_file)
            self.assertTrue(resolve_poc_path(POCS_DIR, poc_file)[0])

    def test_decision_context_uses_runtime_paths(self):
        context = build_decision_poc_context(
            available_params={"target_ip": "127.0.0.1"},
            open_ports=[22],
            coverage_path="/nonexistent/lab/evidence/poc_coverage.json",
        )
        self.assertIn("network/04_CWE_521_SSH_Weak_Credentials_Active_Validation.py", context)
        self.assertNotIn("network/11_SSH_Weak_Creds.py", context)


if __name__ == "__main__":
    unittest.main()

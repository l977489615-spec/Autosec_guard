import unittest
from pathlib import Path

from poc_catalog import resolve_poc_path, resolve_poc_reference

POCS_DIR = str(Path(__file__).resolve().parent / "pocs")


class PocCatalogResolveTests(unittest.TestCase):
    def test_dynamic_planner_token_resolves_to_registered_probe(self):
        resolved, kind = resolve_poc_reference(POCS_DIR, "dynamic_unknown_service_probe")
        self.assertIn(kind, {"alias", "exact"})
        self.assertEqual(resolved, "network/15_CWE_200_Service_Probe_Active_Validation.py")

    def test_legacy_ssh_weak_alias_resolves(self):
        resolved, kind = resolve_poc_reference(POCS_DIR, "network/11_SSH_Weak_Creds.py")
        self.assertIn(kind, {"alias", "exact"})
        self.assertEqual(
            resolved,
            "network/04_CWE_521_SSH_Weak_Credentials_Active_Validation.py",
        )
        self.assertTrue(resolve_poc_path(POCS_DIR, resolved)[0])

    def test_legacy_https_alias_resolves(self):
        resolved, kind = resolve_poc_reference(POCS_DIR, "network/20_HTTPS_No_Cert_Pin.py")
        self.assertIn(kind, {"alias", "exact"})
        self.assertEqual(
            resolved,
            "network/13_CWE_295_HTTPS_No_Cert_Pin_Active_Validation.py",
        )

    def test_exact_runtime_path_unchanged(self):
        path = "network/03_CWE_200_SSH_Service_Active_Validation.py"
        resolved, kind = resolve_poc_reference(POCS_DIR, path)
        self.assertEqual(resolved, path)
        self.assertEqual(kind, "exact")

    def test_unknown_path_stays_unresolved(self):
        resolved, kind = resolve_poc_reference(POCS_DIR, "network/zzzz_not_a_real_poc.py")
        self.assertIsNone(resolved)
        self.assertEqual(kind, "unresolved")


if __name__ == "__main__":
    unittest.main()

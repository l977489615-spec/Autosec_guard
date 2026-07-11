import unittest

from architecture_audit import audit


class ArchitectureAuditTests(unittest.TestCase):
    def test_runtime_has_no_lab_dependency(self):
        report = audit()
        self.assertEqual(report["lab_dependencies"], [])
        self.assertEqual(report["unexpected_oversized_files"], [])


if __name__ == "__main__":
    unittest.main()

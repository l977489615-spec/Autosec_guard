import importlib.util
import os
import sys
import unittest
from pathlib import Path


SERVER_DIR = Path(__file__).resolve().parent
REPO_DIR = SERVER_DIR.parent
XLSX_PATH = REPO_DIR.parent / "connected_vehicle_public_poc_exp_50.xlsx"
sys.path.insert(0, str(SERVER_DIR))
sys.path.insert(0, str(SERVER_DIR / "pocs"))


class PublicPocExpGeneratorContractTest(unittest.TestCase):
    def test_public_generator_skips_existing_cves_and_renders_new_plugins(self):
        from generate_public_poc_exp_plugins import build_plugin_specs, existing_cves, load_records, render_plugin

        records = load_records(XLSX_PATH)
        existing = existing_cves()
        specs = build_plugin_specs(records, existing)

        self.assertEqual(50, len(records))
        self.assertEqual(35, len(specs))
        self.assertEqual(35, len({spec.cve for spec in specs}))
        self.assertTrue(all(spec.cve not in existing for spec in specs))
        self.assertTrue(all(spec.display_id.startswith("POC-") for spec in specs))
        self.assertTrue(all(spec.class_name.startswith("Poc") for spec in specs))
        self.assertTrue(all("_" not in spec.class_name for spec in specs))
        self.assertTrue(all(spec.class_name.endswith("AuditPlugin") for spec in specs))
        self.assertTrue(all(spec.public_poc_url for spec in specs))
        self.assertTrue(all(spec.category in {"application", "network", "wireless", "advanced"} for spec in specs))

        rendered = render_plugin(specs[0])
        legacy_batch_name = "PUBLIC" + "50"
        self.assertNotIn(legacy_batch_name, rendered)
        self.assertNotIn(legacy_batch_name.title(), rendered)
        self.assertIn("public_poc_profile", rendered)
        self.assertIn("source_evidence", rendered)
        self.assertIn("PoC/EXP source", rendered)
        self.assertIn("run_active_validation", rendered)
        self.assertIn("allow_disruptive=true", rendered)
        self.assertIn("requires_manual_review", rendered)
        self.assertNotIn("AUTOSec-LAB-EXP", rendered)

    def test_public_generator_categories_match_attack_surface(self):
        from generate_public_poc_exp_plugins import build_plugin_specs, existing_cves, load_records

        specs = build_plugin_specs(load_records(XLSX_PATH), existing_cves())
        by_cve = {spec.cve: spec for spec in specs}

        self.assertEqual("network", by_cve["CVE-2022-42005"].category)
        self.assertEqual("application", by_cve["CVE-2024-10382"].category)
        self.assertEqual("wireless", by_cve["CVE-2017-13082"].category)
        self.assertEqual("wireless", by_cve["CVE-2020-12352"].category)
        self.assertEqual("application", by_cve["CVE-2015-1538"].category)

    def test_public_specs_are_backed_by_downloaded_source_artifacts(self):
        from generate_public_poc_exp_plugins import build_plugin_specs, existing_cves, load_records, render_plugin

        specs = build_plugin_specs(load_records(XLSX_PATH), existing_cves())
        by_cve = {spec.cve: spec for spec in specs}

        expected_sources = {
            "CVE-2022-42008": "01-ROOT-SHELL-VIA-ODIN.md",
            "CVE-2022-42005": "04-LOG-BACKSHELL-AND-DV-ACCESS.md",
            "CVE-2017-13082": "krack-test-client.py",
            "CVE-2020-26139": "fragattack.py",
            "CVE-2019-9494": "dragonslayer",
            "CVE-2020-12352": "bleedingtooth",
            "CVE-2015-1538": "Stagefright_CVE-2015-1538-1_Exploit.py",
            "CVE-2023-45779": "apex-checker",
            "CVE-2026-0006": "generate_overflow_mp4.py",
            "CVE-2024-47538": "GHSL-2024-115",
        }
        for cve, source_hint in expected_sources.items():
            with self.subTest(cve=cve):
                spec = by_cve[cve]
                evidence_text = " ".join(item.get("path", "") for item in spec.source_evidence)
                self.assertIn(source_hint, evidence_text)
                self.assertTrue(any(item.get("trigger_summary") for item in spec.source_evidence))
                rendered = render_plugin(spec)
                self.assertIn("source_evidence", rendered)
                self.assertIn(source_hint, rendered)

    def test_first_public_plugin_is_importable(self):
        from generate_public_poc_exp_plugins import build_plugin_specs, existing_cves, load_records, render_plugin

        spec = build_plugin_specs(load_records(XLSX_PATH), existing_cves())[0]
        target = SERVER_DIR / "tmp_public_generated_import_check.py"
        target.write_text(render_plugin(spec), encoding="utf-8")
        try:
            module_spec = importlib.util.spec_from_file_location("tmp_public_generated_import_check", target)
            module = importlib.util.module_from_spec(module_spec)
            assert module_spec and module_spec.loader
            module_spec.loader.exec_module(module)
            plugin_cls = getattr(module, spec.class_name)
            self.assertEqual(spec.cve, plugin_cls.meta_cve_id)
            self.assertTrue(plugin_cls.is_disruptive)
        finally:
            try:
                os.remove(target)
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    unittest.main()

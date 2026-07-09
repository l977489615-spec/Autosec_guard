import importlib.util
import os
import sys
import unittest
from pathlib import Path


SERVER_DIR = Path(__file__).resolve().parent
REPO_DIR = SERVER_DIR.parent
XLSX_PATH = REPO_DIR.parent / "connected_vehicle_ivi_vuln_100_nonduplicates.xlsx"
sys.path.insert(0, str(SERVER_DIR))
sys.path.insert(0, str(SERVER_DIR / "pocs"))


class XlsxExpGeneratorContractTest(unittest.TestCase):
    def test_generator_renders_100_unique_active_validation_plugins(self):
        from generate_xlsx_exp_plugins import build_plugin_specs, load_records, render_plugin

        records = load_records(XLSX_PATH)
        specs = build_plugin_specs(records)

        self.assertEqual(100, len(records))
        self.assertEqual(100, len(specs))
        self.assertEqual(100, len({spec.output_path for spec in specs}))
        self.assertEqual(100, len({spec.class_name for spec in specs}))
        self.assertEqual(100, len({spec.display_id for spec in specs}))
        self.assertTrue(all(spec.display_id.startswith("XLSX2-") for spec in specs))
        self.assertTrue(all(spec.category in {"application", "network", "wireless", "advanced"} for spec in specs))

        rendered = render_plugin(specs[0])
        self.assertIn("from active_validation_core import run_active_validation", rendered)
        self.assertIn("from iv_plugin_base import IVIVulnerabilityPlugin", rendered)
        self.assertIn("from local_exp_stimulus import build_local_sample_probe", rendered)
        self.assertIn("requires_manual_review", rendered)
        self.assertIn("allow_disruptive=true", rendered)
        self.assertIn("def exploit(self):", rendered)

    def test_generated_numbers_are_contiguous_inside_each_category(self):
        from generate_xlsx_exp_plugins import build_plugin_specs, load_records

        specs = build_plugin_specs(load_records(XLSX_PATH))
        by_category = {}
        for spec in specs:
            by_category.setdefault(spec.category, []).append(int(spec.output_path.name.split("_", 1)[0]))

        for category, numbers in by_category.items():
            ordered = sorted(numbers)
            self.assertEqual(
                list(range(ordered[0], ordered[0] + len(ordered))),
                ordered,
                f"{category} generated numbers should be contiguous",
            )

    def test_android_aaos_software_stack_uses_application_style_names(self):
        from generate_xlsx_exp_plugins import build_plugin_specs, load_records

        specs = build_plugin_specs(load_records(XLSX_PATH))
        android_app_specs = [
            spec for spec in specs
            if "Android" in spec.vendor_product and "Qualcomm" not in spec.vendor_product
            and "Bluetooth" not in spec.vendor_product
            and "WiFi" not in spec.component
        ]

        self.assertTrue(android_app_specs)
        self.assertTrue(all(spec.category == "application" for spec in android_app_specs))
        self.assertTrue(all("CVE_" not in spec.output_path.name for spec in specs))
        self.assertTrue(any("Android_Framework_EoP_Audit.py" in spec.output_path.name for spec in android_app_specs))

    def test_qualcomm_bsp_items_remain_advanced(self):
        from generate_xlsx_exp_plugins import build_plugin_specs, load_records

        specs = build_plugin_specs(load_records(XLSX_PATH))
        qualcomm_specs = [spec for spec in specs if "Qualcomm" in spec.vendor_product]

        self.assertTrue(qualcomm_specs)
        self.assertTrue(all(spec.category == "advanced" for spec in qualcomm_specs))

    def test_rendered_payloads_are_vulnerability_specific_not_generic_fillers(self):
        from generate_xlsx_exp_plugins import build_plugin_specs, load_records, render_plugin

        specs = build_plugin_specs(load_records(XLSX_PATH))
        rendered_sources = [render_plugin(spec) for spec in specs]

        for source in rendered_sources:
            self.assertNotIn("AUTOSec-LAB-EXP", source)
            self.assertNotIn('b"\\\\xff" * 64', source)
            self.assertNotIn('b"A" * 1024', source)
            self.assertIn("stimulus_profile", source)
            self.assertIn("trigger_family", source)
        self.assertGreater(len(set(rendered_sources)), 90)

    def test_first_rendered_plugin_is_importable_after_write(self):
        from generate_xlsx_exp_plugins import build_plugin_specs, load_records, render_plugin

        spec = build_plugin_specs(load_records(XLSX_PATH))[0]
        target = SERVER_DIR / "tmp_generated_import_check.py"
        target.write_text(render_plugin(spec), encoding="utf-8")
        try:
            module_spec = importlib.util.spec_from_file_location("tmp_generated_import_check", target)
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

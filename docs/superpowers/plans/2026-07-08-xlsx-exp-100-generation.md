# XLSX EXP 100 Generation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate 100 active-validation EXP plugins from `connected_vehicle_ivi_vuln_100_nonduplicates.xlsx`.

**Architecture:** Add a focused Python generator that reads the Excel workbook, maps each row into the existing PoC directory taxonomy, renders an `IVIVulnerabilityPlugin` script using `run_active_validation`, and writes deterministic files with unique names and display IDs. Generated plugins use active lab stimuli and safety gates rather than invented weaponized payloads.

**Tech Stack:** Python 3, `openpyxl`, existing `active_validation_core`, `iv_plugin_base`, `local_exp_stimulus`, `audit_exp_readiness`.

---

### Task 1: Generator Contract

**Files:**
- Create: `server/test_xlsx_exp_generator.py`
- Create: `server/generate_xlsx_exp_plugins.py`

- [ ] Write a failing unittest that loads the workbook, renders 100 plugin specs, checks unique output paths/classes, and verifies rendered source contains `run_active_validation`, `IVIVulnerabilityPlugin`, `allow_disruptive`-protected language, and `requires_manual_review`.
- [ ] Run `python3 -m unittest server/test_xlsx_exp_generator.py` and confirm it fails because `generate_xlsx_exp_plugins` does not exist.
- [ ] Implement `generate_xlsx_exp_plugins.py` with `load_records`, `build_plugin_specs`, `render_plugin`, and `write_plugins`.
- [ ] Re-run the unittest and confirm it passes.

### Task 2: Generate Plugins

**Files:**
- Create: generated files under `server/pocs/application/`, `server/pocs/network/`, `server/pocs/wireless/`, and `server/pocs/advanced/`.

- [ ] Run `python3 server/generate_xlsx_exp_plugins.py /Users/queen/Desktop/ICV_POC_research/connected_vehicle_ivi_vuln_100_nonduplicates.xlsx --write`.
- [ ] Confirm exactly 100 `XLSX2-*` plugin files were created.
- [ ] Confirm each file has unique `meta_display_id`, class name, and `meta_cve_id`.

### Task 3: Verification

**Files:**
- Test existing/generated scripts.

- [ ] Run `python3 -m py_compile` across all newly generated files.
- [ ] Run `python3 -m unittest server/test_xlsx_exp_generator.py server/test_exp_upgrade_contract.py`.
- [ ] Run `python3 server/audit_exp_readiness.py --paths <generated files>` or equivalent audit command supported by the repository.
- [ ] If registry embedding is needed, regenerate `server/generated_poc_registry.py`; otherwise rely on filesystem auto-discovery.

### Self-Review

- No placeholder requirements remain.
- The plan covers Excel ingestion, deterministic rendering, file generation, and verification.
- It avoids modifying unrelated PoCs and does not require manual registry edits for normal filesystem deployments.

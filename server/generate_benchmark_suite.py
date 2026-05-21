#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from benchmark_suite import _normalize_scoring_key, _session_findings, _session_structured


SERVER_DIR = Path(__file__).resolve().parent
DEFAULT_FIXTURE_DIR = SERVER_DIR / "benchmarks" / "fixtures"
DEFAULT_OUTPUT_FILE = SERVER_DIR / "benchmarks" / "default_suite.json"
DEFAULT_REGRESSION_OUTPUT_FILE = SERVER_DIR / "benchmarks" / "regression_suite.json"


def _load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _unique_preserve_order(values: List[str]) -> List[str]:
    seen = set()
    ordered = []
    for value in values:
        key = _normalize_scoring_key(value)
        if not key or key in seen:
            continue
        seen.add(key)
        ordered.append(value)
    return ordered


def _extract_raw_structured_items(structured: dict, phase_names: List[str]) -> List[dict]:
    if not isinstance(structured, dict):
        return []
    for phase_name in phase_names:
        phase = structured.get(phase_name)
        if isinstance(phase, dict):
            items = phase.get("items")
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
    return []


def _extract_raw_plan_names(structured: dict) -> List[str]:
    items = _extract_raw_structured_items(structured, ["attack_plan", "decision"])
    if not items:
        items = _extract_raw_structured_items(structured, ["planner"])

    raw = []
    for item in items:
        value = item.get("poc_name") or item.get("filename") or item.get("name")
        if value:
            raw.append(str(value))
    return _unique_preserve_order(raw)


def _extract_raw_execution_successes(structured: dict) -> List[str]:
    items = _extract_raw_structured_items(structured, ["execution", "execute"])
    raw = []
    for item in items:
        if item.get("vulnerable") or str(item.get("status", "")).lower() == "vulnerable":
            value = item.get("poc_name") or item.get("filename") or item.get("name")
            if value:
                raw.append(str(value))
    return _unique_preserve_order(raw)


def _is_weak_finding(item: dict) -> bool:
    name = str(item.get("name") or item.get("pocId") or item.get("poc_id") or "").strip()
    source = str(item.get("source") or "").strip().lower()
    domain = str(item.get("domain") or "").strip().lower()
    if not name:
        return True
    if "未知漏洞" in name or _normalize_scoring_key(name) == "unknown":
        return True
    if source == "executor_log":
        return True
    if domain == "generic":
        return True
    return False


def _build_benchmark_from_fixture(fixture_path: Path) -> dict:
    payload = _load_json(fixture_path)
    structured = _session_structured(payload)
    findings = _session_findings(payload)
    plan_names = _extract_raw_plan_names(structured)
    execution_successes = _extract_raw_execution_successes(structured)

    required_findings = []
    optional_findings = []
    for item in findings:
        name = str(item.get("name") or item.get("pocId") or item.get("poc_id") or "").strip()
        if not name:
            continue
        if _is_weak_finding(item):
            optional_findings.append(name)
        else:
            required_findings.append(name)

    required_execution = []
    optional_execution = []
    required_findings_norm = {_normalize_scoring_key(item) for item in required_findings}
    for item in execution_successes:
        if _normalize_scoring_key(item) in required_findings_norm:
            required_execution.append(item)
        else:
            optional_execution.append(item)

    session_id = payload.get("session_id") or fixture_path.stem
    benchmark_id = payload.get("benchmark_id") or _normalize_scoring_key(session_id).replace("_", "-")
    target_name = payload.get("targetName") or session_id
    risk_score = payload.get("risk_score", payload.get("riskScore", 0))

    connection = payload.get("connection", {}) if isinstance(payload.get("connection"), dict) else {}
    target_profile = {
        "target_name": target_name,
        "target_ip": connection.get("ip"),
        "mode": payload.get("mode"),
        "has_bluetooth": bool(connection.get("bluetoothMac")),
        "has_can_interface": bool(connection.get("canInterface")),
        "has_wifi_interface": bool(connection.get("interface")),
    }

    return {
        "id": benchmark_id,
        "name": f"Fixture Baseline - {target_name}",
        "fixture_file": str(fixture_path.relative_to(SERVER_DIR)).replace("\\", "/"),
        "source": "fixture",
        "target_profile": target_profile,
        "expected_findings": {
            "required": _unique_preserve_order(required_findings),
            "optional": _unique_preserve_order(optional_findings),
            "forbidden": [],
        },
        "expected_attack_plan": {
            "required": _unique_preserve_order(plan_names),
            "optional": [],
            "forbidden": [],
        },
        "expected_execution": {
            "required": _unique_preserve_order(required_execution),
            "optional": _unique_preserve_order(optional_execution),
            "forbidden": [],
        },
        "min_risk_score": risk_score,
        "pass_threshold": {
            "finding_precision": 0.8,
            "finding_recall": 1.0,
            "plan_required_coverage": 1.0,
            "plan_precision": 0.8,
            "execution_success_coverage": 1.0 if required_execution else 0.5,
            "execution_health": 0.9,
            "min_risk_score": risk_score,
        },
    }


def build_suite(fixtures_dir: Path) -> dict:
    fixture_paths = sorted(path for path in fixtures_dir.glob("*.json") if path.is_file())
    benchmarks = [_build_benchmark_from_fixture(path) for path in fixture_paths]
    return {
        "id": "autosec-default-suite",
        "name": "AutoSec Regression Suite",
        "description": "Auto-generated regression suite derived from fixture sessions.",
        "generator": "server/generate_benchmark_suite.py",
        "fixture_dir": str(fixtures_dir.relative_to(SERVER_DIR)).replace("\\", "/"),
        "benchmark_count": len(benchmarks),
        "benchmarks": benchmarks,
    }


def _benchmark_signal_score(benchmark: dict) -> tuple[int, int, int]:
    findings = benchmark.get("expected_findings", {}) if isinstance(benchmark.get("expected_findings"), dict) else {}
    execution = benchmark.get("expected_execution", {}) if isinstance(benchmark.get("expected_execution"), dict) else {}
    plan = benchmark.get("expected_attack_plan", {}) if isinstance(benchmark.get("expected_attack_plan"), dict) else {}
    return (
        len(findings.get("required", [])),
        len(execution.get("required", [])),
        len(plan.get("required", [])),
    )


def build_regression_suite(full_suite: dict, limit: int = 3) -> dict:
    benchmarks = list(full_suite.get("benchmarks", []) or [])
    ranked = sorted(
        benchmarks,
        key=lambda item: (_benchmark_signal_score(item), item.get("id", "")),
        reverse=True,
    )
    selected = ranked[:max(1, limit)] if ranked else []
    return {
        "id": "autosec-regression-suite",
        "name": "AutoSec Regression Gate",
        "description": "Smaller strict regression gate derived from the highest-signal fixture sessions.",
        "generator": "server/generate_benchmark_suite.py",
        "source_suite": full_suite.get("id"),
        "benchmark_count": len(selected),
        "benchmarks": selected,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate default benchmark suite from fixture sessions.")
    parser.add_argument("--fixtures-dir", type=Path, default=DEFAULT_FIXTURE_DIR, help="Directory containing fixture JSON sessions.")
    parser.add_argument("--output-file", type=Path, default=DEFAULT_OUTPUT_FILE, help="Output suite JSON path.")
    parser.add_argument("--regression-output-file", type=Path, default=DEFAULT_REGRESSION_OUTPUT_FILE, help="Output regression suite JSON path.")
    parser.add_argument("--regression-limit", type=int, default=3, help="Maximum number of benchmarks to keep in regression suite.")
    parser.add_argument("--check", action="store_true", help="Exit non-zero if generated suite differs from files on disk.")
    args = parser.parse_args()

    fixtures_dir = args.fixtures_dir.resolve()
    output_file = args.output_file.resolve()
    regression_output_file = args.regression_output_file.resolve()
    suite = build_suite(fixtures_dir)
    regression_suite = build_regression_suite(suite, limit=args.regression_limit)
    rendered = json.dumps(suite, ensure_ascii=False, indent=2)
    regression_rendered = json.dumps(regression_suite, ensure_ascii=False, indent=2)

    if args.check:
        current_default = output_file.read_text(encoding="utf-8") if output_file.exists() else ""
        current_regression = regression_output_file.read_text(encoding="utf-8") if regression_output_file.exists() else ""
        expected_default = rendered + "\n"
        expected_regression = regression_rendered + "\n"
        if current_default != expected_default or current_regression != expected_regression:
            print(json.dumps({
                "up_to_date": False,
                "default_suite_matches": current_default == expected_default,
                "regression_suite_matches": current_regression == expected_regression,
                "message": "Benchmark suite files are stale. Run python3 server/generate_benchmark_suite.py",
            }, ensure_ascii=False, indent=2))
            return 1
        print(json.dumps({
            "up_to_date": True,
            "default_suite_matches": True,
            "regression_suite_matches": True,
        }, ensure_ascii=False, indent=2))
        return 0

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(rendered + "\n", encoding="utf-8")
    regression_output_file.parent.mkdir(parents=True, exist_ok=True)
    regression_output_file.write_text(regression_rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

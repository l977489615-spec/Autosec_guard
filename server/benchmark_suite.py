import json
from pathlib import Path
from typing import Any, Dict, List, Optional


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_SUITE_PATH = BASE_DIR / "benchmarks" / "default_suite.json"


def _normalize_scoring_key(value: Any) -> str:
    return str(value or "").strip().lower().replace("\\", "/").replace(" ", "_")


def _extract_structured_phase_items(structured: dict, phase_names: List[str]) -> List[dict]:
    if not isinstance(structured, dict):
        return []
    for phase_name in phase_names:
        phase = structured.get(phase_name)
        if isinstance(phase, dict):
            items = phase.get("items")
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
    return []


def _session_findings(session_payload: dict) -> List[dict]:
    if not isinstance(session_payload, dict):
        return []

    findings = session_payload.get("findings")
    if isinstance(findings, list) and findings:
        return [item for item in findings if isinstance(item, dict)]

    results = session_payload.get("results")
    if isinstance(results, list):
        return [
            item
            for item in results
            if isinstance(item, dict) and item.get("vulnerable", True)
        ]

    return []


def _session_structured(session_payload: dict) -> dict:
    if not isinstance(session_payload, dict):
        return {}
    structured = session_payload.get("structured")
    return structured if isinstance(structured, dict) else {}


def _session_phase_records(session_payload: dict) -> List[dict]:
    if not isinstance(session_payload, dict):
        return []
    phase_records = session_payload.get("phase_records")
    return phase_records if isinstance(phase_records, list) else []


def _normalize_named_items(items: List[dict], field_candidates: List[str]) -> List[str]:
    normalized = []
    for item in items:
        if not isinstance(item, dict):
            continue
        value = None
        for candidate in field_candidates:
            if item.get(candidate):
                value = item.get(candidate)
                break
        key = _normalize_scoring_key(value)
        if key:
            normalized.append(key)
    return normalized


def _normalize_list_items(items: List[Any], dict_fields: List[str]) -> List[str]:
    normalized = []
    for item in items or []:
        if isinstance(item, dict):
            value = None
            for field_name in dict_fields:
                if item.get(field_name):
                    value = item.get(field_name)
                    break
            key = _normalize_scoring_key(value)
        else:
            key = _normalize_scoring_key(item)
        if key:
            normalized.append(key)
    return sorted(set(normalized))


def _parse_expected_groups(spec: Any, *, dict_fields: List[str]) -> Dict[str, List[str]]:
    if isinstance(spec, dict):
        return {
            "required": _normalize_list_items(spec.get("required", []), dict_fields),
            "optional": _normalize_list_items(spec.get("optional", []), dict_fields),
            "forbidden": _normalize_list_items(spec.get("forbidden", []), dict_fields),
        }

    if isinstance(spec, list):
        return {
            "required": _normalize_list_items(spec, dict_fields),
            "optional": [],
            "forbidden": [],
        }

    return {"required": [], "optional": [], "forbidden": []}


def _extract_actual_plan_names(structured: dict) -> List[str]:
    attack_plan = _extract_structured_phase_items(structured, ["attack_plan", "decision"])
    if attack_plan:
        return _normalize_named_items(attack_plan, ["poc_name", "filename", "name"])

    planner_items = _extract_structured_phase_items(structured, ["planner"])
    return _normalize_named_items(planner_items, ["poc_name", "filename", "name"])


def _extract_actual_execution_items(structured: dict) -> List[dict]:
    return _extract_structured_phase_items(structured, ["execution", "execute"])


def _extract_actual_execution_successes(structured: dict) -> List[str]:
    items = _extract_actual_execution_items(structured)
    successes = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("vulnerable") or str(item.get("status", "")).lower() == "vulnerable":
            key = _normalize_scoring_key(item.get("poc_name") or item.get("filename") or item.get("name"))
            if key:
                successes.append(key)
    return sorted(set(successes))


def _ratio(numerator: int, denominator: int, default: float = 1.0) -> float:
    if denominator <= 0:
        return default
    return round(numerator / denominator, 3)


def load_benchmark_suite(path: Optional[str | Path] = None) -> dict:
    suite_path = Path(path) if path else DEFAULT_SUITE_PATH
    if suite_path.exists():
        with suite_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    return {
        "id": "autosec-default-suite",
        "name": "AutoSec Regression Suite",
        "description": "Fallback suite used when the JSON definition is missing.",
        "benchmarks": [],
    }


def validate_benchmark_suite(suite: dict) -> dict:
    errors: List[str] = []
    warnings: List[str] = []

    if not isinstance(suite, dict):
        return {"valid": False, "errors": ["suite must be a JSON object"], "warnings": []}

    benchmarks = suite.get("benchmarks")
    if not isinstance(benchmarks, list):
        return {"valid": False, "errors": ["suite.benchmarks must be a list"], "warnings": []}

    seen_ids = set()
    for index, benchmark in enumerate(benchmarks, start=1):
        if not isinstance(benchmark, dict):
            errors.append(f"benchmark[{index}] must be an object")
            continue

        benchmark_id = benchmark.get("id")
        if not benchmark_id:
            errors.append(f"benchmark[{index}] missing id")
        elif benchmark_id in seen_ids:
            errors.append(f"duplicate benchmark id: {benchmark_id}")
        else:
            seen_ids.add(benchmark_id)

        for field_name in ("expected_findings", "expected_attack_plan", "expected_execution"):
            field_value = benchmark.get(field_name, {})
            parsed = _parse_expected_groups(
                field_value,
                dict_fields=["id", "name", "pocId", "poc_id", "poc_name", "filename"],
            )
            overlap_required_optional = set(parsed["required"]).intersection(parsed["optional"])
            overlap_required_forbidden = set(parsed["required"]).intersection(parsed["forbidden"])
            overlap_optional_forbidden = set(parsed["optional"]).intersection(parsed["forbidden"])
            if overlap_required_optional:
                errors.append(f"{benchmark_id}.{field_name} has overlap between required and optional")
            if overlap_required_forbidden:
                errors.append(f"{benchmark_id}.{field_name} has overlap between required and forbidden")
            if overlap_optional_forbidden:
                errors.append(f"{benchmark_id}.{field_name} has overlap between optional and forbidden")
            if not parsed["required"] and field_name != "expected_execution":
                warnings.append(f"{benchmark_id}.{field_name} has no required entries")

        threshold = benchmark.get("pass_threshold", {})
        if threshold and not isinstance(threshold, dict):
            errors.append(f"{benchmark_id}.pass_threshold must be an object")
            continue
        for key in (
            "finding_precision",
            "finding_recall",
            "plan_required_coverage",
            "plan_precision",
            "execution_success_coverage",
            "execution_health",
        ):
            if key in threshold:
                value = threshold.get(key)
                if not isinstance(value, (int, float)) or value < 0 or value > 1:
                    errors.append(f"{benchmark_id}.pass_threshold.{key} must be between 0 and 1")

        min_risk_score = threshold.get("min_risk_score", benchmark.get("min_risk_score"))
        if min_risk_score is not None and not isinstance(min_risk_score, (int, float)):
            errors.append(f"{benchmark_id}.min_risk_score must be numeric")

    return {"valid": not errors, "errors": errors, "warnings": warnings}


def score_session_against_benchmark(session_payload: dict, benchmark: dict) -> dict:
    findings = _session_findings(session_payload)
    structured = _session_structured(session_payload)
    phase_records = _session_phase_records(session_payload)

    actual_findings = sorted(set(_normalize_named_items(findings, ["name", "pocId", "poc_id"])))
    actual_findings_set = set(actual_findings)

    expected_findings = _parse_expected_groups(
        benchmark.get("expected_findings", []),
        dict_fields=["id", "name", "pocId", "poc_id"],
    )
    required_findings = set(expected_findings["required"])
    optional_findings = set(expected_findings["optional"])
    forbidden_findings = set(expected_findings["forbidden"])
    allowed_findings = required_findings | optional_findings
    matched_required_findings = sorted(actual_findings_set.intersection(required_findings))
    matched_allowed_findings = sorted(actual_findings_set.intersection(allowed_findings))
    unexpected_findings = sorted(actual_findings_set - allowed_findings) if allowed_findings else []
    forbidden_found = sorted(actual_findings_set.intersection(forbidden_findings))

    actual_plan_names = _extract_actual_plan_names(structured)
    actual_plan_set = set(actual_plan_names)
    expected_plan = _parse_expected_groups(
        benchmark.get("expected_attack_plan", []),
        dict_fields=["id", "poc_name", "filename", "name"],
    )
    required_plan = set(expected_plan["required"])
    optional_plan = set(expected_plan["optional"])
    forbidden_plan = set(expected_plan["forbidden"])
    allowed_plan = required_plan | optional_plan
    matched_required_plan = sorted(actual_plan_set.intersection(required_plan))
    matched_allowed_plan = sorted(actual_plan_set.intersection(allowed_plan))
    unexpected_plan = sorted(actual_plan_set - allowed_plan) if allowed_plan else []
    forbidden_plan_found = sorted(actual_plan_set.intersection(forbidden_plan))

    expected_execution = _parse_expected_groups(
        benchmark.get("expected_execution", {}),
        dict_fields=["id", "poc_name", "filename", "name"],
    )
    required_successes = set(expected_execution["required"])
    optional_successes = set(expected_execution["optional"])
    forbidden_successes = set(expected_execution["forbidden"])
    allowed_successes = required_successes | optional_successes
    actual_successes = set(_extract_actual_execution_successes(structured))
    matched_required_successes = sorted(actual_successes.intersection(required_successes))
    matched_allowed_successes = sorted(actual_successes.intersection(allowed_successes))
    forbidden_successes_found = sorted(actual_successes.intersection(forbidden_successes))

    actual_execution = _extract_actual_execution_items(structured)
    actual_execution_errors = sum(
        1 for item in actual_execution if isinstance(item, dict) and item.get("error")
    )
    execution_health = round(max(0.0, 1.0 - (actual_execution_errors / max(len(actual_execution), 1))), 3)

    expected_min_risk = benchmark.get("min_risk_score")
    risk_score = session_payload.get("risk_score", session_payload.get("riskScore", 0)) if isinstance(session_payload, dict) else 0

    finding_recall = _ratio(len(matched_required_findings), len(required_findings))
    finding_precision = _ratio(len(matched_allowed_findings), len(actual_findings_set))
    plan_required_coverage = _ratio(len(matched_required_plan), len(required_plan))
    plan_precision = _ratio(len(matched_allowed_plan), len(actual_plan_set))
    execution_success_coverage = _ratio(len(matched_required_successes), len(required_successes))
    execution_success_precision = _ratio(len(matched_allowed_successes), len(actual_successes))

    threshold = benchmark.get("pass_threshold", {})
    threshold_finding_precision = threshold.get("finding_precision", 0.5)
    threshold_finding_recall = threshold.get("finding_recall", 0.5)
    threshold_plan_required_coverage = threshold.get("plan_required_coverage", threshold.get("plan_coverage", 0.5))
    threshold_plan_precision = threshold.get("plan_precision", 0.5)
    threshold_execution_success_coverage = threshold.get("execution_success_coverage", 0.5)
    threshold_execution_health = threshold.get("execution_health", 0.5)
    threshold_risk_score = threshold.get("min_risk_score", expected_min_risk)
    threshold_forbidden_finding_count = threshold.get(
        "forbidden_finding_count_max",
        0 if forbidden_findings else None,
    )
    threshold_forbidden_plan_count = threshold.get(
        "forbidden_plan_step_count_max",
        0 if forbidden_plan else None,
    )
    threshold_forbidden_execution_count = threshold.get(
        "forbidden_execution_success_count_max",
        0 if forbidden_successes else None,
    )

    passed = (
        finding_precision >= threshold_finding_precision
        and finding_recall >= threshold_finding_recall
        and plan_required_coverage >= threshold_plan_required_coverage
        and plan_precision >= threshold_plan_precision
        and execution_success_coverage >= threshold_execution_success_coverage
        and execution_health >= threshold_execution_health
        and (threshold_risk_score is None or risk_score >= threshold_risk_score)
        and (
            threshold_forbidden_finding_count is None
            or len(forbidden_found) <= threshold_forbidden_finding_count
        )
        and (
            threshold_forbidden_plan_count is None
            or len(forbidden_plan_found) <= threshold_forbidden_plan_count
        )
        and (
            threshold_forbidden_execution_count is None
            or len(forbidden_successes_found) <= threshold_forbidden_execution_count
        )
    )

    return {
        "benchmark_id": benchmark.get("id"),
        "benchmark_name": benchmark.get("name") or benchmark.get("id") or "unnamed-benchmark",
        "session_id": session_payload.get("session_id"),
        "risk_score": risk_score,
        "expected_min_risk_score": expected_min_risk,
        "actual_findings": actual_findings,
        "matched_required_findings": matched_required_findings,
        "unexpected_findings": unexpected_findings,
        "forbidden_findings_found": forbidden_found,
        "actual_finding_count": len(actual_findings_set),
        "expected_required_finding_count": len(required_findings),
        "finding_precision": finding_precision,
        "finding_recall": finding_recall,
        "actual_plan": actual_plan_names,
        "matched_required_plan": matched_required_plan,
        "unexpected_plan_steps": unexpected_plan,
        "forbidden_plan_steps_found": forbidden_plan_found,
        "actual_plan_count": len(actual_plan_set),
        "expected_required_plan_count": len(required_plan),
        "plan_required_coverage": plan_required_coverage,
        "plan_precision": plan_precision,
        "actual_execution_successes": sorted(actual_successes),
        "matched_required_execution_successes": matched_required_successes,
        "forbidden_execution_successes_found": forbidden_successes_found,
        "expected_required_execution_success_count": len(required_successes),
        "execution_success_coverage": execution_success_coverage,
        "execution_success_precision": execution_success_precision,
        "execution_error_count": actual_execution_errors,
        "execution_health": execution_health,
        "phase_count": len(phase_records),
        "pass_threshold": threshold,
        "passed": passed,
    }


def score_benchmark_suite(session_payload: dict, suite: Optional[dict] = None) -> dict:
    suite = suite or load_benchmark_suite()
    benchmarks = suite.get("benchmarks", []) or []
    scores = [score_session_against_benchmark(session_payload, benchmark) for benchmark in benchmarks]
    if scores:
        average_precision = round(sum(score["finding_precision"] for score in scores) / len(scores), 3)
        average_recall = round(sum(score["finding_recall"] for score in scores) / len(scores), 3)
        average_plan_coverage = round(sum(score["plan_required_coverage"] for score in scores) / len(scores), 3)
        average_plan_precision = round(sum(score["plan_precision"] for score in scores) / len(scores), 3)
        average_execution_success_coverage = round(sum(score["execution_success_coverage"] for score in scores) / len(scores), 3)
        average_execution_health = round(sum(score["execution_health"] for score in scores) / len(scores), 3)
    else:
        average_precision = average_recall = average_plan_coverage = 0.0
        average_plan_precision = average_execution_success_coverage = average_execution_health = 0.0

    return {
        "suite_id": suite.get("id", "autosec-default-suite"),
        "suite_name": suite.get("name", "AutoSec Regression Suite"),
        "benchmark_count": len(benchmarks),
        "passed_count": sum(1 for score in scores if score["passed"]),
        "scores": scores,
        "aggregate": {
            "average_precision": average_precision,
            "average_recall": average_recall,
            "average_plan_coverage": average_plan_coverage,
            "average_plan_precision": average_plan_precision,
            "average_execution_success_coverage": average_execution_success_coverage,
            "average_execution_health": average_execution_health,
        },
    }

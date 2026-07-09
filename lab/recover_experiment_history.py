#!/usr/bin/env python3
"""Rebuild experiment aggregates from timestamped raw agent reports."""
from __future__ import annotations

import argparse
import copy
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from compare_global_vs_agent import build_comparison
from run_experiment import read_json, write_json


FILENAME_PATTERN = re.compile(r"^(?P<task_id>AGENT-(?P<variant_id>.+))_(?P<ts>\d{8}_\d{6})\.json$")


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in {"", None}:
            return default
        return int(value)
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value in {"", None}:
            return default
        return float(value)
    except Exception:
        return default


def _variant_label_from_id(variant_id: str) -> str:
    return variant_id.replace("-", " ").strip() or variant_id


def _load_baseline_by_target(target_dir: Path) -> dict[str, dict]:
    rows = read_json(target_dir / "scan_baseline_summary.json", []) or []
    return {
        str(item.get("target_id") or ""): item
        for item in rows
        if isinstance(item, dict) and item.get("target_id")
    }


def _summarize_agent_report(report_path: Path, target_id: str, target_name: str, target_type: str, baseline: dict) -> dict:
    match = FILENAME_PATTERN.match(report_path.name)
    report = read_json(report_path, {}) or {}
    structured = report.get("structured", {}) or {}
    llm_usage = report.get("llm_usage") or structured.get("llm_usage") or {}
    llm_totals = llm_usage.get("totals") or {}
    attack_plan = structured.get("attack_plan", {}).get("items", []) or []
    execution = structured.get("execution", {}).get("items", []) or []
    reflector = structured.get("reflector", {}) or {}
    phase_records = report.get("phase_records", []) or []
    phase_status = Counter(str(item.get("status") or "") for item in phase_records)
    findings = report.get("findings", []) or []

    variant_id = match.group("variant_id") if match else "UNKNOWN"
    task_id = match.group("task_id") if match else report_path.stem
    duration = _safe_float(report.get("duration_seconds") or report.get("elapsed_seconds"))
    prompt_tokens = _safe_int(llm_totals.get("prompt_tokens"))
    completion_tokens = _safe_int(llm_totals.get("completion_tokens"))
    total_tokens = _safe_int(llm_totals.get("total_tokens"))
    llm_calls = _safe_int(llm_totals.get("calls"))
    tool_calls = _safe_int(llm_totals.get("tool_call_count"))
    finding_count = len(findings)
    executed_pocs = len(execution)
    manual_review_required_count = sum(1 for item in execution if item.get("requires_human_review"))
    manual_review_pending_count = sum(
        1 for item in execution
        if str(item.get("verification_status") or "") == "pending_manual_review"
    )
    manual_review_confirmed_count = sum(
        1 for item in execution
        if str(item.get("verification_status") or "").startswith("manual_confirmed_")
    )
    baseline_completed = _safe_int(baseline.get("global_completed_poc_count"))
    baseline_applicable = _safe_int(baseline.get("global_applicable_poc_count"))

    return {
        "task_id": task_id,
        "target_id": target_id,
        "target_name": target_name,
        "target_type": target_type,
        "target_ip": report.get("target_ip", ""),
        "method": "ours_full",
        "variant_id": variant_id,
        "variant_label": _variant_label_from_id(variant_id),
        "fast_model": next(iter((llm_usage.get("per_model") or {}).keys()), ""),
        "strong_model": "",
        "report_model": "",
        "planned_poc_count": len(attack_plan),
        "executed_poc_count": executed_pocs,
        "reflection_reentry_count": int(report.get("reflector_reentry_count", 0) or 0),
        "reflection_next_action": reflector.get("next_action", ""),
        "reflection_issue_count": len(reflector.get("issues", []) or []),
        "retry_or_error_count": sum(1 for item in execution if item.get("error")),
        "finding_count": finding_count,
        "phase_done_count": phase_status.get("done", 0),
        "phase_error_count": phase_status.get("error", 0),
        "phase_skipped_count": phase_status.get("skipped", 0),
        "attack_surface_gate": bool(structured.get("attack_surface_gate", {}).get("blocked")),
        "manual_review_required_count": manual_review_required_count,
        "manual_review_pending_count": manual_review_pending_count,
        "manual_review_confirmed_count": manual_review_confirmed_count,
        "manual_review_wait_seconds": _safe_float(report.get("manual_review_wait_seconds")),
        "llm_call_count": llm_calls,
        "llm_tool_call_count": tool_calls,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "avg_llm_latency_ms": _safe_float(llm_totals.get("avg_latency_ms")),
        "tokens_per_finding": round(total_tokens / finding_count, 2) if finding_count > 0 else "",
        "findings_per_minute": round(finding_count / max(duration / 60.0, 0.001), 3) if duration > 0 else "",
        "executions_per_minute": round(executed_pocs / max(duration / 60.0, 0.001), 3) if duration > 0 else "",
        "global_applicable_poc_count": baseline_applicable,
        "global_completed_poc_count": baseline_completed,
        "global_vulnerable_count": _safe_int(baseline.get("global_vulnerable_count")),
        "global_elapsed_seconds": _safe_float(baseline.get("global_elapsed_seconds")),
        "agent_execution_coverage_vs_global": round(executed_pocs / max(baseline_completed, 1), 4) if baseline_completed else "",
        "agent_plan_coverage_vs_global_applicable": round(executed_pocs / max(baseline_applicable, 1), 4) if baseline_applicable else "",
        "elapsed_seconds": duration,
        "report_file": str(report_path),
        "error": report.get("error", ""),
    }


def _build_model_comparison_payload(rows: list[dict], target_id: str, target_name: str) -> dict:
    return {
        "generated_at": "",
        "target_id": target_id,
        "target_ip": rows[0].get("target_ip") if rows else "",
        "target_name": target_name,
        "variant_count": len(rows),
        "total_elapsed_seconds": round(sum(_safe_float(row.get("elapsed_seconds")) for row in rows), 3),
        "variants": [
            {
                "variant_id": row.get("variant_id"),
                "variant_label": row.get("variant_label"),
                "fast_model": row.get("fast_model"),
                "strong_model": row.get("strong_model"),
                "report_model": row.get("report_model"),
                "elapsed_seconds": row.get("elapsed_seconds"),
                "planned_poc_count": row.get("planned_poc_count"),
                "executed_poc_count": row.get("executed_poc_count"),
                "finding_count": row.get("finding_count"),
                "llm_call_count": row.get("llm_call_count"),
                "prompt_tokens": row.get("prompt_tokens"),
                "completion_tokens": row.get("completion_tokens"),
                "total_tokens": row.get("total_tokens"),
                "avg_llm_latency_ms": row.get("avg_llm_latency_ms"),
                "tokens_per_finding": row.get("tokens_per_finding"),
                "findings_per_minute": row.get("findings_per_minute"),
                "executions_per_minute": row.get("executions_per_minute"),
                "global_completed_poc_count": row.get("global_completed_poc_count"),
                "agent_execution_coverage_vs_global": row.get("agent_execution_coverage_vs_global"),
                "reflection_reentry_count": row.get("reflection_reentry_count"),
                "retry_or_error_count": row.get("retry_or_error_count"),
                "attack_surface_gate": row.get("attack_surface_gate"),
                "phase_done_count": row.get("phase_done_count"),
                "phase_error_count": row.get("phase_error_count"),
                "success": not row.get("error"),
                "report_file": row.get("report_file"),
            }
            for row in rows
        ],
        "raw_rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Recover aggregate experiment files from raw agent_runs reports.")
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--target-id", default="")
    parser.add_argument("--target-name", default="")
    parser.add_argument("--target-type", default="mock")
    args = parser.parse_args()

    target_dir = args.target_dir
    target_id = args.target_id or target_dir.name
    target_name = args.target_name or target_id
    baseline_by_target = _load_baseline_by_target(target_dir)
    baseline = baseline_by_target.get(target_id, {})

    rows: list[dict] = []
    for report_path in sorted((target_dir / "agent_runs").glob("*.json")):
        rows.append(_summarize_agent_report(report_path, target_id, target_name, args.target_type, baseline))

    rows.sort(key=lambda item: (str(item.get("variant_id")), str(item.get("report_file"))))
    model_payload = _build_model_comparison_payload(rows, target_id, target_name)

    model_path = target_dir / "model_comparison.recovered.json"
    orchestration_path = target_dir / "agent_orchestration.recovered.json"
    comparison_seed = target_dir / "comparison.recovered.seed.json"
    comparison_path = target_dir / "comparison.recovered.json"

    write_json(model_path, model_payload)
    write_json(orchestration_path, rows)

    write_json(comparison_seed, [])
    original_model = target_dir / "model_comparison.json"
    original_comparison = target_dir / "comparison.json"
    backup_model = None
    backup_comparison = None
    if original_model.exists():
        backup_model = original_model.with_suffix(".json.bak_recovery_tmp")
        original_model.rename(backup_model)
    if original_comparison.exists():
        backup_comparison = original_comparison.with_suffix(".json.bak_recovery_tmp")
        original_comparison.rename(backup_comparison)
    try:
        write_json(original_model, model_payload)
        write_json(original_comparison, [])
        recovered_comparison = build_comparison(target_dir, target_id)
        write_json(comparison_path, recovered_comparison)
    finally:
        if original_model.exists():
            original_model.unlink()
        if original_comparison.exists():
            original_comparison.unlink()
        comparison_seed.unlink(missing_ok=True)
        if backup_model:
            backup_model.rename(original_model)
        if backup_comparison:
            backup_comparison.rename(original_comparison)

    print(json.dumps({
        "target_id": target_id,
        "recovered_variants": len(rows),
        "model_comparison": str(model_path),
        "agent_orchestration": str(orchestration_path),
        "comparison": str(comparison_path),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

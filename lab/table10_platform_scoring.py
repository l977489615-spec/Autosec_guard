#!/usr/bin/env python3
"""Score and aggregate Table 10 platform rows across MOCK-LOCAL / IVI-01 / REAL-CAR."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_vulnerability_hits import agent_positive_hits, agent_vulnerable_poc_files
from execution_metrics import all_execution_items, execution_sets
LAB = Path(__file__).resolve().parent
ROOT = LAB.parent
EVIDENCE_ROOT = LAB / "evidence"
PGPT_CATALOG = LAB / "pentestgpt_id4" / "poc_catalog.json"
REAL_CAR_MANIFEST = LAB / "pentestgpt_id4" / "private" / "id4_evaluation_manifest.json"
MANIFEST_CACHE = LAB / "table10_manifests"

TABLE10_TARGETS = ("MOCK-LOCAL", "IVI-01", "REAL-CAR")

PLATFORM_REPORT_SETS: dict[str, dict[str, str]] = {
    "ZHIPU_MULTI": {
        "MOCK-LOCAL": "agent_runs/AGENT-ZHIPU_20260604_034605.json",
        "IVI-01": "agent_runs/AGENT-ZHIPU_20260604_005621.json",
        "REAL-CAR": "agent_runs/AGENT-ZHIPU_20260607_225808.json",
    },
    "GPT_MULTI": {
        "MOCK-LOCAL": "agent_runs/AGENT-GPT_20260604_012123.json",
        "IVI-01": "agent_runs/AGENT-GPT_20260604_011302.json",
        "REAL-CAR": "agent_runs/AGENT-GPT_20260603_235956.json",
    },
    "GPT_SINGLE": {
        "MOCK-LOCAL": "agent_runs/SINGLE-GPT_20260604_012105.json",
        "IVI-01": "agent_runs/SINGLE-GPT_20260604_011220.json",
        "REAL-CAR": "agent_runs/SINGLE-GPT_20260603_235906.json",
    },
}


def safe_ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _report_target_id(report: dict, report_path: Path | None) -> str:
    target_id = str(report.get("target_id") or "").strip()
    if target_id:
        return target_id
    if report_path and report_path.parent.name == "agent_runs" and len(report_path.parents) >= 2:
        return report_path.parents[1].name
    return ""


def _report_duration_seconds(report: dict) -> float:
    manual_wait = float(report.get("manual_review_wait_seconds") or 0)
    elapsed = float(report.get("duration_seconds") or 0)
    if elapsed:
        return max(elapsed - manual_wait, 0.0)
    execution = (((report.get("structured") or {}).get("execution") or {}).get("items") or [])
    execution_elapsed = sum(float(item.get("elapsed_seconds") or 0) for item in execution)
    llm_elapsed = float(
        ((report.get("llm_usage") or {}).get("totals") or {}).get("latency_ms_total") or 0
    ) / 1000
    return max(execution_elapsed + llm_elapsed - manual_wait, 0.0)


def load_catalog_maps() -> tuple[dict[str, str], dict[str, str]]:
    catalog = json.loads(PGPT_CATALOG.read_text(encoding="utf-8"))
    by_file = {item["poc_file"]: item["poc_id"] for item in catalog.get("pocs") or []}
    by_id = {item["poc_id"]: item["poc_file"] for item in catalog.get("pocs") or []}
    return by_file, by_id


def poc_file_from_id(poc_id_value: str, *, by_id: dict[str, str]) -> str:
    return by_id.get(poc_id_value, poc_id_value)


def unique_global_positive_poc_files(evidence_root: Path | None = None) -> set[str]:
    """Same baseline as Table 6: vulnerable poc_file deduplicated across three targets."""
    root = evidence_root or EVIDENCE_ROOT
    positives: set[str] = set()
    for target_id in TABLE10_TARGETS:
        scan_path = root / target_id / "scan_results.json"
        if not scan_path.is_file():
            continue
        for row in json.loads(scan_path.read_text(encoding="utf-8")):
            poc_file = str(row.get("poc_file") or "")
            if poc_file and bool(row.get("vulnerable")):
                positives.add(poc_file)
    return positives


def manifest_for_target(target_id: str, *, by_file: dict[str, str] | None = None) -> dict:
    if target_id == "REAL-CAR":
        return json.loads(REAL_CAR_MANIFEST.read_text(encoding="utf-8"))

    cached = MANIFEST_CACHE / f"{target_id}_evaluation_manifest.json"
    if cached.is_file():
        return json.loads(cached.read_text(encoding="utf-8"))

    by_file = by_file or load_catalog_maps()[0]
    scan_path = EVIDENCE_ROOT / target_id / "scan_results.json"
    rows = json.loads(scan_path.read_text(encoding="utf-8"))
    tasks: list[dict] = []
    for index, row in enumerate(rows):
        if not bool(row.get("vulnerable")):
            continue
        poc_file = str(row.get("poc_file") or "")
        poc_id = by_file.get(poc_file, poc_file)
        tasks.append({
            "task_id": f"{target_id}-GT-{index:03d}",
            "attack_surface": poc_file.split("/", 1)[0] if "/" in poc_file else "network",
            "description": f"Validate baseline positive for {poc_file}",
            "expected_pocs": [poc_id],
            "acceptable_pocs": [],
            "positive_pocs": [poc_id],
            "included": True,
            "source": f"scan_results.json vulnerable row ({target_id})",
        })
    manifest = {
        "schema_version": 1,
        "target_id": target_id,
        "private": True,
        "frozen": True,
        "tasks": tasks,
    }
    MANIFEST_CACHE.mkdir(parents=True, exist_ok=True)
    cached.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest


def score_platform_report(
    report_path: Path,
    *,
    manifest: dict | None = None,
    target_id: str | None = None,
    evidence_root: Path | None = None,
) -> dict[str, Any]:
    evidence_root = evidence_root or EVIDENCE_ROOT
    report = json.loads(report_path.read_text(encoding="utf-8"))
    resolved_target = target_id or _report_target_id(report, report_path)
    manifest = manifest or manifest_for_target(resolved_target)
    by_file, by_id = load_catalog_maps()

    def poc_id(item: dict) -> str:
        name = str(item.get("poc_name") or "")
        return by_file.get(name, name)

    def ids_to_files(poc_ids: set[str]) -> set[str]:
        return {poc_file_from_id(poc, by_id=by_id) for poc in poc_ids}

    structured = report.get("structured") or {}
    plan = (structured.get("attack_plan") or {}).get("items") or []
    execution = all_execution_items(report)
    buckets = execution_sets(
        execution,
        poc_id,
        target_id=resolved_target,
        evidence_root=evidence_root,
        dedupe_by_poc=True,
        repo_root=ROOT,
    )
    selected = {poc_id(item) for item in plan}
    agent_vuln_files = agent_vulnerable_poc_files(report)
    tasks = [task for task in manifest.get("tasks") or [] if task.get("included", True)]
    expected = {poc for task in tasks for poc in task.get("expected_pocs") or []}
    positives = {poc for task in tasks for poc in task.get("positive_pocs") or []}
    positive_files = ids_to_files(positives)
    expected_files = ids_to_files(expected)
    selected_hit_files = ids_to_files(selected & expected)
    risk_hit_files = agent_positive_hits(report, positive_files)
    completed_task_files: set[str] = set()
    evidence = buckets["evidence"]
    completed = buckets["completed"]
    completed_tasks = 0
    for task in tasks:
        task_pocs = set(task.get("expected_pocs") or []) | set(task.get("acceptable_pocs") or [])
        if task_pocs & evidence:
            completed_tasks += 1
            completed_task_files |= ids_to_files(task_pocs)
    archived = len(evidence & completed)
    selected_hit = len(selected & expected)
    risk_hit = len(risk_hit_files)
    task_total = len(tasks)
    started_count = len(buckets["started"])
    completed_count = len(completed)
    expected_count = len(expected)
    positive_count = len(positives)

    return {
        "target_id": resolved_target,
        "report_file": str(report_path),
        "model": str(report.get("variant_id") or report.get("variant_label") or ""),
        "completed_poc_count": completed_count,
        "archived_evidence_count": archived,
        "poc_selection_num": selected_hit,
        "poc_selection_den": expected_count,
        "poc_selection_recall": safe_ratio(selected_hit, expected_count),
        "risk_num": risk_hit,
        "risk_den": positive_count,
        "risk_recall": safe_ratio(risk_hit, positive_count),
        "coverage_num": completed_tasks,
        "coverage_den": task_total,
        "coverage_rate": safe_ratio(completed_tasks, task_total),
        "task_num": completed_tasks,
        "task_den": task_total,
        "execution_num": completed_count,
        "execution_den": started_count,
        "execution_completion_rate": safe_ratio(completed_count, started_count),
        "evidence_num": archived,
        "evidence_den": completed_count,
        "evidence_archive_rate": safe_ratio(archived, completed_count),
        "duration_seconds": _report_duration_seconds(report),
        "authorization_required_count": sum(
            1 for item in execution if item.get("requires_human_review")
        ),
        "operator_skipped_count": len(buckets["operator_skipped"]),
        "positive_poc_files": sorted(positive_files),
        "selected_hit_poc_files": sorted(selected_hit_files),
        "risk_hit_poc_files": sorted(risk_hit_files),
        "completed_task_poc_files": sorted(completed_task_files),
    }


def aggregate_platform_scores(per_target_scores: list[dict]) -> dict[str, Any]:
    if not per_target_scores:
        raise ValueError("per_target_scores is empty")

    totals = {
        "completed_poc_count": 0,
        "execution_num": 0,
        "execution_den": 0,
        "evidence_num": 0,
        "evidence_den": 0,
        "authorization_required_count": 0,
    }
    selected_hit_files: set[str] = set()
    risk_hit_files: set[str] = set()
    completed_task_files: set[str] = set()
    durations: list[float] = []
    target_ids: list[str] = []
    report_files: list[str] = []

    for score in per_target_scores:
        target_ids.append(str(score.get("target_id") or ""))
        report_files.append(str(score.get("report_file") or ""))
        selected_hit_files |= set(score.get("selected_hit_poc_files") or [])
        risk_hit_files |= set(score.get("risk_hit_poc_files") or [])
        completed_task_files |= set(score.get("completed_task_poc_files") or [])
        for key in totals:
            totals[key] += int(score.get(key) or 0)
        durations.append(float(score.get("duration_seconds") or 0))

    global_positives = unique_global_positive_poc_files()
    baseline_den = len(global_positives)
    poc_selection_num = len(selected_hit_files & global_positives)
    risk_num = len(risk_hit_files & global_positives)
    coverage_num = len(completed_task_files & global_positives)
    macro_hits = [(int(s.get("risk_num") or 0), int(s.get("risk_den") or 0)) for s in per_target_scores]

    from metric_definitions import (
        coverage_metrics,
        macro_success_metrics,
    )

    avg_duration = sum(durations) / len(durations) if durations else 0.0
    return {
        "target_ids": target_ids,
        "report_files": report_files,
        "per_target": per_target_scores,
        "model": per_target_scores[0].get("model", ""),
        "risk_num": risk_num,
        "risk_den": baseline_den,
        "risk_recall": safe_ratio(risk_num, baseline_den),
        "coverage_num": coverage_num,
        "coverage_den": baseline_den,
        "coverage_rate": safe_ratio(coverage_num, baseline_den),
        **coverage_metrics(coverage_num, baseline_den),
        **macro_success_metrics(macro_hits),
        "duration_seconds": avg_duration,
        "duration_seconds_per_target": durations,
        "authorization_required_count": totals["authorization_required_count"],
        "baseline_positive_poc_files": sorted(global_positives),
        "aggregation_note": (
            "Primary=Recall@GT (30-union); Progress Rate=executed+archived benchmark tasks; "
            "Macro SR=per-target Recall@GT macro average"
        ),
        "hit_rule": "execution.vulnerable=True ∪ report.findings（与表6/7/8 相同）",
        # legacy keys for internal tooling only
        "task_num": coverage_num,
        "task_den": baseline_den,
        "completed_poc_count": totals["completed_poc_count"],
    }


def score_platform_report_set(set_id: str) -> dict[str, Any]:
    mapping = PLATFORM_REPORT_SETS.get(set_id)
    if not mapping:
        raise KeyError(f"unknown platform report set: {set_id}")
    per_target: list[dict] = []
    for target_id in TABLE10_TARGETS:
        rel = mapping.get(target_id)
        if not rel:
            raise FileNotFoundError(f"{set_id} missing report for {target_id}")
        report_path = EVIDENCE_ROOT / target_id / rel
        if not report_path.is_file():
            raise FileNotFoundError(f"missing report: {report_path}")
        manifest = manifest_for_target(target_id)
        per_target.append(score_platform_report(report_path, manifest=manifest, target_id=target_id))
    return aggregate_platform_scores(per_target)


def completed_task_poc_files_from_report(
    report_path: Path | str,
    *,
    evidence_root: Path | None = None,
    target_id: str | None = None,
) -> set[str]:
    path = Path(str(report_path))
    if not path.is_file():
        return set()
    root = evidence_root or EVIDENCE_ROOT
    score = score_platform_report(path, evidence_root=root, target_id=target_id)
    return set(score.get("completed_task_poc_files") or [])


def union_completed_task_poc_files(
    report_paths: list[Path | str],
    *,
    evidence_root: Path | None = None,
) -> set[str]:
    files: set[str] = set()
    for raw in report_paths:
        files |= completed_task_poc_files_from_report(raw, evidence_root=evidence_root)
    return files


def global_task_completion_from_reports(
    report_paths: list[Path | str],
    baseline_poc_files: set[str],
    *,
    evidence_root: Path | None = None,
) -> dict[str, Any]:
    from metric_definitions import task_completion_metrics

    completed_files = union_completed_task_poc_files(report_paths, evidence_root=evidence_root)
    hits = completed_files & baseline_poc_files
    metrics = task_completion_metrics(len(hits), len(baseline_poc_files))
    metrics["completed_task_poc_files"] = sorted(hits)
    return metrics


def write_manifest_cache() -> None:
    by_file, _ = load_catalog_maps()
    for target_id in ("MOCK-LOCAL", "IVI-01"):
        manifest_for_target(target_id, by_file=by_file)


if __name__ == "__main__":
    write_manifest_cache()
    for set_id in PLATFORM_REPORT_SETS:
        agg = score_platform_report_set(set_id)
        print(
            set_id,
            f"漏洞检出 {agg['risk_num']}/{agg['risk_den']}",
            f"任务 {agg['task_num']}/{agg['task_den']}",
            f"耗时均值 {agg['duration_seconds']/60:.2f} min",
        )

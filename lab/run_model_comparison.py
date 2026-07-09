#!/usr/bin/env python3
"""同一目标、多模型 Agent 扫描对比（一晚实验专用）。"""
from __future__ import annotations

import argparse
import copy
import json
import sys
import time
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent
ROOT = LAB_DIR.parent
SERVER_DIR = ROOT / "server"
for path in (LAB_DIR, SERVER_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from run_experiment import (
    build_baseline_replay_pocs_by_target,
    merge_ai_config,
    now_id,
    read_json,
    run_agent_tasks,
    write_json,
)
from artifacts import snapshot_json_artifact


def _merge_ai_config(base: dict, override: dict) -> dict:
    return merge_ai_config(base, override)


def resolve_target_task_template(config: dict, target_id: str | None) -> dict:
    if not target_id:
        block = config.get("model_comparison") or {}
        template = dict(block.get("target_task_template") or {})
        if template:
            return template
        raise ValueError("model_comparison.target_task_template 为空；请使用 --target-id 或在配置中填写 agent_profile")

    target = find_scan_target(config, target_id)
    profile = dict(target.get("agent_profile") or {})
    if not profile:
        raise ValueError(f"target {target_id} 缺少 agent_profile")
    profile.setdefault("target_id", target.get("target_id"))
    profile.setdefault("target_type", target.get("target_type", ""))
    profile.setdefault("target_name", target.get("target_name", ""))
    profile.setdefault("candidate_ports", target.get("candidate_ports", ""))
    profile.setdefault("use_global_recon_seed", True)
    profile.setdefault("use_enhanced_recon", True)
    return profile


def find_scan_target(config: dict, target_id: str) -> dict:
    for item in config.get("scan_targets", []):
        if item.get("target_id") == target_id:
            return item
    raise KeyError(f"scan_targets 中未找到 target_id={target_id}")


def build_model_tasks(config: dict, target_id: str | None = None) -> list[dict]:
    block = config.get("model_comparison") or {}
    template = resolve_target_task_template(config, target_id)
    variants = block.get("variants") or []
    if not template or not variants:
        raise ValueError("model_comparison 需要 target_task_template 与 variants")

    tasks: list[dict] = []
    for variant in variants:
        variant_id = str(variant.get("variant_id") or variant.get("label") or "MODEL")
        task = {
            **template,
            "task_id": f"AGENT-{variant_id}",
            "variant_id": variant_id,
            "variant_label": variant.get("label", variant_id),
            "method": variant.get("method") or template.get("method") or "ours_full",
            "ai_config": merge_ai_config(config.get("ai_config", {}), variant.get("ai_config", {})),
        }
        strong_model = str(task["ai_config"].get("strong_model") or "").strip()
        if strong_model:
            task["ai_config"]["core_model"] = strong_model
        task.setdefault("target_id", template.get("target_id", target_id or ""))
        task.setdefault("target_type", template.get("target_type", ""))
        exp_opts = config.get("experiment_agent_options") or {}
        if task.get("skip_assessment_report") is None:
            task["skip_assessment_report"] = exp_opts.get("skip_assessment_report", True)
        tasks.append(task)
    return tasks


def summarize_variants(rows: list[dict]) -> list[dict]:
    summary = []
    for row in rows:
        summary.append({
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
            "baseline_replay_poc_count": row.get("baseline_replay_poc_count"),
            "attack_surface_gate": row.get("attack_surface_gate"),
            "phase_done_count": row.get("phase_done_count"),
            "phase_error_count": row.get("phase_error_count"),
            "success": not row.get("error"),
            "report_file": row.get("report_file"),
        })
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Run multi-model Agent comparison on one target.")
    parser.add_argument("--config", type=Path, default=Path("lab/experiment_config.full.json"))
    parser.add_argument("--output-dir", type=Path, default=Path("lab/evidence"))
    parser.add_argument("--target-id", default="", help="从 scan_targets[].agent_profile 读取连接参数")
    parser.add_argument("--variant-id", action="append", default=[], help="只跑指定 variant_id，可重复")
    args = parser.parse_args()

    if not args.config.is_file():
        fallback = Path("lab/experiment_config.local.json")
        if fallback.is_file():
            args.config = fallback
    config = read_json(args.config)
    run_id = now_id()
    target_id = args.target_id.strip() or None
    tasks = build_model_tasks(config, target_id=target_id)
    if args.variant_id:
        allowed = {item.strip() for item in args.variant_id if item.strip()}
        tasks = [task for task in tasks if task.get("variant_id") in allowed]

    started = time.time()
    comparison_config = copy.deepcopy(config)
    comparison_config["agent_tasks"] = tasks
    baseline_rows = read_json(args.output_dir / "scan_baseline_summary.json", []) or []
    baseline_by_target = {
        str(item.get("target_id") or ""): item
        for item in baseline_rows
        if isinstance(item, dict) and item.get("target_id")
    }
    scan_rows = read_json(args.output_dir / "scan_results.json", []) or []
    replay_by_target = build_baseline_replay_pocs_by_target(scan_rows if isinstance(scan_rows, list) else [])
    for task in tasks:
        task_target_id = str(task.get("target_id") or target_id or "")
        if task_target_id in replay_by_target:
            task["baseline_replay_pocs"] = replay_by_target[task_target_id]
    rows = run_agent_tasks(comparison_config, args.output_dir, baseline_by_target=baseline_by_target)
    summary = summarize_variants(rows)

    payload = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target_id": target_id or "",
        "target_ip": tasks[0].get("target_ip") if tasks else "",
        "target_name": tasks[0].get("target_name") if tasks else "",
        "variant_count": len(rows),
        "total_elapsed_seconds": round(time.time() - started, 3),
        "variants": summary,
        "raw_rows": rows,
    }
    write_json(args.output_dir / "model_comparison.json", payload)
    snapshot_json_artifact(args.output_dir / "model_comparison.json", payload, run_id)

    # 合并进 agent_orchestration.json（追加，便于 Excel 一张表看完）
    orch_path = args.output_dir / "agent_orchestration.json"
    existing = read_json(orch_path, []) if orch_path.exists() else []
    if not isinstance(existing, list):
        existing = []
    write_json(orch_path, existing + rows)
    snapshot_json_artifact(orch_path, rows, run_id)

    print(json.dumps({"variant_count": len(rows), "output": str(args.output_dir / "model_comparison.json")}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

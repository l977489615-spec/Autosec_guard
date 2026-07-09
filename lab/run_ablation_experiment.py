#!/usr/bin/env python3
"""Run paper ablation experiments: single-agent baseline vs multi-agent full system."""
from __future__ import annotations

import argparse
import copy
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

LAB_DIR = Path(__file__).resolve().parent
ROOT = LAB_DIR.parent
SERVER_DIR = ROOT / "server"
for path in (LAB_DIR, SERVER_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from artifacts import snapshot_json_artifact
from run_experiment import (
    build_baseline_replay_pocs_by_target,
    merge_ai_config,
    now_id,
    order_poc_names_recon_first,
    read_json,
    resolve_pending_manual_review,
    run_agent_tasks,
    run_poc_api,
    should_block,
    summarize_scan_baseline,
    write_json,
)
from run_model_comparison import build_model_tasks


SINGLE_AGENT_PROMPT = """你是单智能体车联网漏洞验证助手。你没有角色分工，必须独立完成侦察理解、PoC选择、执行计划和证据要求定义。
要求：
1. 只能从候选 PoC 清单中选择 poc_file，不能编造文件名。
2. 优先选择 Global 已检出阳性的 PoC，但不要机械全选；体现单智能体有限规划能力。
3. 避免高风险或缺少目标能力的 PoC。
4. 输出严格 JSON：{"plan":[{"poc_name":"...","reason":"...","priority":1}]}。
"""


def _variant_task(config: dict, target_id: str, variant_id: str) -> dict:
    tasks = build_model_tasks(config, target_id=target_id)
    for task in tasks:
        if task.get("variant_id") == variant_id:
            ai_config = task.setdefault("ai_config", {})
            strong_model = str(ai_config.get("strong_model") or "").strip()
            if strong_model:
                ai_config["core_model"] = strong_model
            return task
    raise KeyError(f"variant_id={variant_id} not found")


def _target_from_config(config: dict, target_id: str) -> dict:
    for target in config.get("scan_targets", []) or []:
        if target.get("target_id") == target_id:
            return target
    raise KeyError(f"target_id={target_id} not found")


def _meta_by_poc(output_dir: Path) -> dict[str, dict]:
    coverage = read_json(output_dir / "poc_coverage.json", {}) or read_json(output_dir.parent / "poc_coverage.json", {}) or {}
    return {item.get("poc_file"): item for item in coverage.get("pocs", []) or [] if item.get("poc_file")}


def _candidate_context(scan_rows: list[dict], meta_by_file: dict[str, dict]) -> list[dict]:
    seen: set[str] = set()
    candidates: list[dict] = []
    for row in scan_rows:
        poc = str(row.get("poc_file") or "").strip()
        if not poc or poc in seen:
            continue
        seen.add(poc)
        meta = meta_by_file.get(poc, {})
        candidates.append({
            "poc_file": poc,
            "poc_name": row.get("poc_name") or meta.get("poc_name") or poc,
            "category": row.get("category") or meta.get("category", ""),
            "attack_surface": row.get("attack_surface") or meta.get("attack_surface", ""),
            "global_vulnerable": row.get("vulnerable") is True,
            "status": row.get("status", ""),
            "required_params": meta.get("required_params", ""),
            "destructive_level": meta.get("destructive_level", ""),
        })
    return candidates


def _parse_single_agent_plan(raw: str, allowed: set[str], fallback: list[str], max_steps: int) -> list[str]:
    match = re.search(r"\{[\s\S]*\}", raw or "")
    selected: list[str] = []
    if match:
        try:
            payload = json.loads(match.group(0))
            items = payload.get("plan") or payload.get("items") or []
            for item in items:
                if isinstance(item, dict):
                    poc = str(item.get("poc_name") or item.get("poc_file") or "").strip()
                else:
                    poc = str(item or "").strip()
                if poc in allowed and poc not in selected:
                    selected.append(poc)
        except Exception:
            selected = []
    for poc in fallback:
        if len(selected) >= max_steps:
            break
        if poc in allowed and poc not in selected:
            selected.append(poc)
    return selected[:max_steps]


def _call_single_agent(config: dict, task: dict, candidates: list[dict], max_steps: int) -> tuple[str, dict]:
    from agent_orchestrator import QwenAgent

    llm_config = merge_ai_config(config.get("ai_config", {}) or {}, task.get("ai_config", {}) or {})
    logs: list[dict] = []
    agent = QwenAgent(
        "单智能体Baseline",
        SINGLE_AGENT_PROMPT,
        [],
        api_key=llm_config.get("api_key", ""),
        base_url=llm_config.get("base_url", ""),
        model_name=llm_config.get("core_model") or llm_config.get("strong_model") or llm_config.get("fast_model") or "",
        max_turns=1,
        on_log=lambda item: logs.append(item),
        request_timeout_seconds=int(llm_config.get("llm_timeout_seconds") or 120),
        connect_timeout_seconds=int(llm_config.get("llm_connect_timeout_seconds") or 15),
    )
    context = json.dumps({
        "target": {
            "target_id": task.get("target_id"),
            "target_ip": task.get("target_ip"),
            "target_type": task.get("target_type"),
            "candidate_ports": task.get("candidate_ports", ""),
        },
        "candidate_pocs": candidates,
        "max_plan_steps": max_steps,
    }, ensure_ascii=False)
    raw = agent.call("请生成单智能体 PoC 验证计划。", context=context)
    summary = agent.usage_summary()
    usage = {
        "totals": summary,
        "per_model": {
            str(summary.get("model_name") or agent._model_name): summary,
        },
    }
    usage["logs"] = logs
    return raw, usage


def _execute_single_plan(config: dict, output_dir: Path, target: dict, pocs: list[str], meta_by_file: dict[str, dict], run_id: str) -> tuple[list[dict], float]:
    rows: list[dict] = []
    manual_wait = 0.0
    params_base = {
        "target_ip": target.get("target_ip"),
        "candidate_ports": target.get("candidate_ports", ""),
    }
    if target.get("can_interface"):
        params_base["can_interface"] = target.get("can_interface")
    if target.get("expected_usb_serial"):
        params_base["expected_usb_serial"] = target.get("expected_usb_serial")
    if target.get("bluetooth_mac"):
        params_base["bluetooth_mac"] = target.get("bluetooth_mac")
        params_base["bd_addr"] = target.get("bluetooth_mac")
        params_base["target_mac"] = target.get("bluetooth_mac")

    for index, poc in enumerate(pocs, start=1):
        params = dict(params_base)
        blocked, reason, meta = should_block(meta_by_file, poc, params)
        session_id = f"SINGLE-{target.get('target_id')}_{poc.rsplit('/', 1)[-1]}_{run_id}_{index}"
        started = time.time()
        if blocked:
            result = {
                "success": False,
                "blocked": True,
                "requires_approval": True,
                "error": reason,
                "vulnerable": False,
                "evidence": "",
                "elapsed_seconds": 0,
            }
        else:
            result = run_poc_api(config.get("api_base", "http://127.0.0.1:5002"), poc, params, session_id)
            result = resolve_pending_manual_review(
                config,
                config.get("api_base", "http://127.0.0.1:5002"),
                result=result,
                session_id=session_id,
                poc_id=poc,
                poc_name=meta.get("poc_name", poc),
                target_ip=str(target.get("target_ip") or ""),
                target_mac=str(params.get("target_mac") or ""),
            )
        elapsed = result.get("elapsed_seconds", round(time.time() - started, 3))
        manual_wait += float(result.get("manual_review_wait_seconds") or 0)
        evidence_file = output_dir / "poc_runs" / f"{session_id}.json"
        write_json(evidence_file, result)
        status = "blocked" if result.get("blocked") or result.get("requires_approval") else ("error" if result.get("error") or result.get("success") is False else "completed")
        rows.append({
            "step": index,
            "poc_name": poc,
            "status": status,
            "vulnerable": result.get("vulnerable") is True,
            "error": result.get("error", ""),
            "elapsed_seconds": elapsed,
            "requires_human_review": bool(result.get("requires_human_review")),
            "verification_status": result.get("verification_status", ""),
            "evidence_file": str(evidence_file),
        })
    return rows, round(manual_wait, 3)


def run_single_agent(config: dict, output_dir: Path, target_id: str, variant_id: str, run_id: str, max_steps: int) -> dict:
    target = _target_from_config(config, target_id)
    task = _variant_task(config, target_id, variant_id)
    scan_rows = read_json(output_dir / "scan_results.json", []) or []
    meta_by_file = _meta_by_poc(output_dir)
    candidates = _candidate_context(scan_rows, meta_by_file)
    allowed = {item["poc_file"] for item in candidates}
    global_positive = [item["poc_file"] for item in candidates if item.get("global_vulnerable")]
    fallback = global_positive + [item["poc_file"] for item in candidates]
    fallback = order_poc_names_recon_first(fallback)
    started = time.time()
    raw_plan, usage = _call_single_agent(config, task, candidates, max_steps)
    plan = order_poc_names_recon_first(_parse_single_agent_plan(raw_plan, allowed, fallback, max_steps))
    execution, manual_wait = _execute_single_plan(config, output_dir, target, plan, meta_by_file, run_id)
    elapsed = round(time.time() - started - manual_wait, 3)
    findings = [item for item in execution if item.get("vulnerable")]
    report = {
        "ablation_group": "single_agent",
        "target_id": target_id,
        "variant_id": variant_id,
        "raw_plan": raw_plan,
        "structured": {
            "attack_plan": {"items": [{"step": i + 1, "poc_name": poc} for i, poc in enumerate(plan)]},
            "execution": {"items": execution},
        },
        "findings": [{"name": item["poc_name"], "source": "single_agent_execution"} for item in findings],
        "llm_usage": usage,
    }
    report_file = output_dir / "agent_runs" / f"SINGLE-{variant_id}_{run_id}.json"
    write_json(report_file, report)
    return {
        "group_id": "A",
        "ablation_group": "single_agent",
        "system_config": "单智能体",
        "target_id": target_id,
        "variant_id": variant_id,
        "planned_poc_count": len(plan),
        "executed_poc_count": len(execution),
        "finding_count": len(findings),
        "error_count": sum(1 for item in execution if item.get("error")),
        "manual_review_required_count": sum(1 for item in execution if item.get("requires_human_review")),
        "manual_review_wait_seconds": manual_wait,
        "elapsed_seconds": elapsed,
        "llm_call_count": (usage.get("totals") or {}).get("calls", ""),
        "total_tokens": (usage.get("totals") or {}).get("total_tokens", ""),
        "report_file": str(report_file),
        "data_source": "real_single_agent_run",
    }


def run_multi_agent(config: dict, output_dir: Path, target_id: str, variant_id: str, run_id: str) -> dict:
    task = _variant_task(config, target_id, variant_id)
    scan_rows = read_json(output_dir / "scan_results.json", []) or []
    replay_by_target = build_baseline_replay_pocs_by_target(scan_rows if isinstance(scan_rows, list) else [])
    if target_id in replay_by_target:
        task["baseline_replay_pocs"] = replay_by_target[target_id]
    comparison_config = copy.deepcopy(config)
    comparison_config["agent_tasks"] = [task]
    baseline_by_target = summarize_scan_baseline(scan_rows if isinstance(scan_rows, list) else [])
    rows = run_agent_tasks(comparison_config, output_dir, baseline_by_target=baseline_by_target, run_id=run_id)
    row = rows[0] if rows else {}
    return {
        "group_id": "D",
        "ablation_group": "multi_agent_full",
        "system_config": "多智能体+反思+Global baseline replay",
        **row,
        "data_source": "real_multi_agent_run",
    }


def attach_ablation_metrics(rows: list[dict], output_dir: Path) -> list[dict]:
    scan_rows = read_json(output_dir / "scan_results.json", []) or []
    global_vuln = {
        row.get("poc_file")
        for row in scan_rows
        if row.get("vulnerable") is True and row.get("poc_file")
    }
    for row in rows:
        report = read_json(ROOT / str(row.get("report_file", "")), None)
        if report is None:
            report = read_json(Path(str(row.get("report_file", ""))), {}) or {}
        execution = ((report.get("structured") or {}).get("execution") or {}).get("items") or []
        vuln_pocs = {
            item.get("poc_name") or item.get("poc_file")
            for item in execution
            if item.get("vulnerable") is True
        }
        overlap = sorted(global_vuln & vuln_pocs)
        row["global_vulnerable_count"] = len(global_vuln)
        row["finding_overlap_with_global"] = len(overlap)
        row["finding_overlap_pocs"] = overlap
        row["task_completion_rate"] = round(len(overlap) / max(len(global_vuln), 1), 4) if global_vuln else ""
        row["effective_evidence_rate"] = round(row.get("finding_count", 0) / max(row.get("executed_poc_count", 0), 1), 4) if row.get("executed_poc_count") else ""
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Run single-agent vs multi-agent ablation experiment.")
    parser.add_argument("--config", type=Path, default=Path("lab/experiment_config.local.json"))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--variant-id", default="QWEN-MAX")
    parser.add_argument("--mode", choices=["single", "multi", "all"], default="all")
    parser.add_argument("--single-max-steps", type=int, default=6)
    args = parser.parse_args()

    config = read_json(args.config)
    run_id = now_id()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "agent_runs").mkdir(exist_ok=True)
    (args.output_dir / "poc_runs").mkdir(exist_ok=True)
    rows: list[dict] = []
    if args.mode in {"single", "all"}:
        rows.append(run_single_agent(config, args.output_dir, args.target_id, args.variant_id, run_id, args.single_max_steps))
    if args.mode in {"multi", "all"}:
        rows.append(run_multi_agent(config, args.output_dir, args.target_id, args.variant_id, run_id))
    rows = attach_ablation_metrics(rows, args.output_dir)
    payload = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target_id": args.target_id,
        "variant_id": args.variant_id,
        "run_id": run_id,
        "rows": rows,
    }
    write_json(args.output_dir / "ablation_results.json", payload)
    snapshot_json_artifact(args.output_dir / "ablation_results.json", payload, run_id)
    print(json.dumps({"output": str(args.output_dir / "ablation_results.json"), "rows": len(rows)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

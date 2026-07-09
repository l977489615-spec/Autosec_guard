#!/usr/bin/env python3
"""完整实验矩阵：逐 target 执行 Global 扫描 + 多模型 Agent + 可选 IVI/CAN。"""
from __future__ import annotations

import argparse
import copy
import json
import subprocess
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
    collect_edge_capability,
    collect_manual_comparison,
    collect_poc_coverage,
    read_json,
    run_scan_targets,
    summarize_scan_baseline,
    write_json,
)
from run_model_comparison import build_model_tasks, summarize_variants, find_scan_target
from run_experiment import run_agent_tasks
from artifacts import snapshot_file_artifact, snapshot_json_artifact


def build_ground_truth_hint(output_dir: Path, scan_rows: list[dict]) -> None:
    positives = sorted({
        row.get("poc_file")
        for row in scan_rows
        if row.get("vulnerable") is True and row.get("status") == "completed" and row.get("poc_file")
    })
    payload = {
        "target_id": scan_rows[0].get("target_id") if scan_rows else "",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "positive_pocs": positives,
        "negative_pocs": sorted({
            row.get("poc_file")
            for row in scan_rows
            if row.get("vulnerable") is False and row.get("status") == "completed" and row.get("poc_file")
        }),
        "notes": "由 Global 扫描自动生成，请人工确认后复制为 lab/ground_truth/<TARGET_ID>.json",
    }
    write_json(output_dir / "ground_truth_hint.json", payload)


def run_target(
    config: dict,
    target_id: str,
    evidence_root: Path,
    variant_ids: list[str],
    skip_global: bool,
    skip_agent: bool,
    api_base: str,
) -> dict:
    target = find_scan_target(config, target_id)
    run_id = time.strftime("%Y%m%d_%H%M%S")
    flags = target.get("experiment_flags") or {}
    output_dir = evidence_root / target_id
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "poc_runs").mkdir(exist_ok=True)
    (output_dir / "agent_runs").mkdir(exist_ok=True)

    summary = {"target_id": target_id, "target_type": target.get("target_type", ""), "output_dir": str(output_dir), "steps": []}
    coverage = read_json(evidence_root / "poc_coverage.json") if (evidence_root / "poc_coverage.json").exists() else collect_poc_coverage()

    scan_rows: list[dict] = []
    if not skip_global and flags.get("run_global_scan", True):
        scan_config = copy.deepcopy(config)
        scan_config["scan_targets"] = [target]
        scan_rows = run_scan_targets(scan_config, coverage, output_dir)
        write_json(output_dir / "scan_baseline_summary.json", list(summarize_scan_baseline(scan_rows).values()))
        snapshot_file_artifact(output_dir / "resolved_scan_targets.json", run_id)
        snapshot_file_artifact(output_dir / "scan_results.json", run_id)
        snapshot_file_artifact(output_dir / "scan_baseline_summary.json", run_id)
        summary["steps"].append({"step": "global_scan", "poc_count": len(scan_rows)})
        if flags.get("build_ground_truth_hint"):
            build_ground_truth_hint(output_dir, scan_rows)
        gt_script = LAB_DIR / "sync_ground_truth.py"
        if gt_script.is_file() and scan_rows:
            subprocess.run(
                [
                    sys.executable,
                    str(gt_script),
                    "--target-id",
                    target_id,
                    "--scan-results",
                    str(output_dir / "scan_results.json"),
                ],
                cwd=str(ROOT),
                check=False,
            )

    if flags.get("run_ivi_new"):
        if target.get("auto_select", True):
            summary["steps"].append({
                "step": "ivi_new",
                "skipped": True,
                "reason": "new/ 与主库 PoC 已并入 Global scan_results.json 统一统计",
            })
        else:
            serial = target.get("expected_usb_serial") or ""
            cmd = [sys.executable, str(LAB_DIR / "run_ivi_new_batch.py"), "--output-dir", str(output_dir)]
            if serial and not str(serial).startswith("REPLACE"):
                cmd.extend(["--serial", serial])
            for poc in config.get("ivi_new_poc_selection") or []:
                cmd.extend(["--poc", poc])
            proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
            summary["steps"].append({"step": "ivi_new", "returncode": proc.returncode, "stdout_tail": proc.stdout[-500:]})

    if not skip_agent and flags.get("run_agent_models", True):
        agent_config = copy.deepcopy(config)
        agent_config.setdefault("model_comparison", {})
        agent_config["model_comparison"]["target_task_template"] = dict(target.get("agent_profile") or {})
        tasks = build_model_tasks(agent_config)
        if variant_ids:
            allowed = set(variant_ids)
            tasks = [task for task in tasks if task.get("variant_id") in allowed]
        replay_by_target = build_baseline_replay_pocs_by_target(scan_rows)
        for task in tasks:
            task_target_id = str(task.get("target_id") or target_id or "")
            if task_target_id in replay_by_target:
                task["baseline_replay_pocs"] = replay_by_target[task_target_id]
        agent_config["agent_tasks"] = tasks
        baseline_by_target = summarize_scan_baseline(scan_rows) if scan_rows else {}
        started = time.time()
        rows = run_agent_tasks(agent_config, output_dir, baseline_by_target=baseline_by_target, run_id=run_id)
        payload = {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target_id": target_id,
            "target_type": target.get("target_type", ""),
            "target_ip": tasks[0].get("target_ip") if tasks else "",
            "target_name": tasks[0].get("target_name") if tasks else "",
            "variant_count": len(rows),
            "total_elapsed_seconds": round(time.time() - started, 3),
            "variants": summarize_variants(rows),
            "raw_rows": rows,
        }
        write_json(output_dir / "model_comparison.json", payload)
        snapshot_json_artifact(output_dir / "model_comparison.json", payload, run_id)
        summary["steps"].append({"step": "agent_models", "variant_count": len(rows)})

    if flags.get("run_can"):
        can_if = target.get("can_interface") or "can0"
        script = LAB_DIR / "collect_can_passive.sh"
        proc = subprocess.run(["bash", str(script), can_if, "15"], cwd=str(ROOT), capture_output=True, text=True)
        can_csv = LAB_DIR / "can_test_records.csv"
        if can_csv.is_file():
            (output_dir / "can_test_records.csv").write_text(can_csv.read_text(encoding="utf-8"), encoding="utf-8")
        summary["steps"].append({"step": "can_passive", "returncode": proc.returncode})

    edge_rows = collect_edge_capability(config, output_dir)
    snapshot_file_artifact(output_dir / "edge_capabilities.json", run_id)
    if scan_rows:
        collect_manual_comparison(config, scan_rows, output_dir)
        snapshot_file_artifact(output_dir / "comparison.json", run_id)

    compare_script = LAB_DIR / "compare_global_vs_agent.py"
    if compare_script.is_file() and (output_dir / "scan_results.json").is_file() and (output_dir / "model_comparison.json").is_file():
        subprocess.run(
            [sys.executable, str(compare_script), "--target-dir", str(output_dir), "--target-id", target_id, "--run-id", run_id],
            cwd=str(ROOT),
            check=False,
        )

    typical = [item for item in config.get("typical_cases", []) if item.get("target_id") == target_id]
    if typical:
        write_json(output_dir / "typical_cases.json", typical)
        snapshot_json_artifact(output_dir / "typical_cases.json", typical, run_id)

    write_json(output_dir / "target_summary.json", summary)
    snapshot_json_artifact(output_dir / "target_summary.json", summary, run_id)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Run full experiment matrix target by target.")
    parser.add_argument("--config", type=Path, default=Path("lab/experiment_config.full.json"))
    parser.add_argument("--evidence-root", type=Path, default=Path("lab/evidence"))
    parser.add_argument("--target-id", action="append", default=[], help="只跑指定 target，可重复")
    parser.add_argument("--variant-id", action="append", default=[], help="只跑指定模型变体，可重复")
    parser.add_argument("--skip-global", action="store_true")
    parser.add_argument("--skip-agent", action="store_true")
    parser.add_argument("--skip-workbook", action="store_true")
    args = parser.parse_args()

    config = read_json(args.config)
    args.evidence_root.mkdir(parents=True, exist_ok=True)

    coverage = collect_poc_coverage()
    write_json(args.evidence_root / "poc_coverage.json", coverage)
    snapshot_json_artifact(args.evidence_root / "poc_coverage.json", coverage, time.strftime("%Y%m%d_%H%M%S"))
    collect_edge_capability(config, args.evidence_root)

    order = config.get("experiment_run_order") or [t.get("target_id") for t in config.get("scan_targets", [])]
    if args.target_id:
        order = [item for item in order if item in set(args.target_id)]

    results = []
    for target_id in order:
        if not target_id:
            continue
        print(f"\n========== TARGET: {target_id} ==========", flush=True)
        try:
            summary = run_target(
                config,
                target_id,
                args.evidence_root,
                args.variant_id,
                args.skip_global,
                args.skip_agent,
                config.get("api_base", "http://127.0.0.1:5002"),
            )
            results.append(summary)
            if not args.skip_workbook:
                can_records = args.evidence_root / target_id / "can_test_records.csv"
                wb_cmd = [
                    sys.executable,
                    str(LAB_DIR / "build_experiment_workbook.py"),
                    "--experiment-dir",
                    str(args.evidence_root / target_id),
                    "--output",
                    str(args.evidence_root / target_id / "实验数据统计表.xlsx"),
                ]
                if can_records.is_file():
                    wb_cmd.extend(["--can-records", str(can_records)])
                subprocess.run(wb_cmd, cwd=str(ROOT), check=False)
        except Exception as exc:
            results.append({"target_id": target_id, "error": str(exc)})

    write_json(args.evidence_root / "full_experiment_summary.json", {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "config": str(args.config),
        "targets": results,
    })

    if not args.skip_workbook:
        subprocess.run(
            [
                sys.executable,
                str(LAB_DIR / "build_paper_workbook.py"),
                "--evidence-root",
                str(args.evidence_root),
                "--config",
                str(args.config),
                "--output",
                str(ROOT / "lab" / "论文实验数据汇总.xlsx"),
            ],
            cwd=str(ROOT),
            check=False,
        )

    print(json.dumps({
        "targets_run": len(results),
        "evidence_root": str(args.evidence_root),
        "paper_workbook": str(ROOT / "lab" / "论文实验数据汇总.xlsx"),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

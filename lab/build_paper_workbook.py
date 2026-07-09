#!/usr/bin/env python3
"""合并各 target 证据，生成论文用总表 lab/论文实验数据汇总.xlsx"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter


def read_json(path: Path, default: Any):
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def read_csv(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_sheet(wb: Workbook, title: str, headers: list[str], rows: list[dict]):
    ws = wb.create_sheet(title)
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True)
        cell.fill = PatternFill("solid", fgColor="D9EAF7")
    for row in rows:
        ws.append([row.get(header, "") for header in headers])
    for index, header in enumerate(headers, start=1):
        width = max(12, len(str(header)) + 2)
        for row_index in range(2, min(ws.max_row, 120) + 1):
            width = max(width, min(45, len(str(ws.cell(row_index, index).value or "")) + 2))
        ws.column_dimensions[get_column_letter(index)].width = width
    ws.freeze_panes = "A2"


def discover_targets(evidence_root: Path) -> list[str]:
    targets = []
    for path in sorted(evidence_root.iterdir()):
        if path.is_dir() and (path / "scan_results.json").is_file():
            targets.append(path.name)
    return targets


def main() -> int:
    parser = argparse.ArgumentParser(description="Build merged paper workbook from all target evidence dirs.")
    parser.add_argument("--evidence-root", type=Path, default=Path("lab/evidence"))
    parser.add_argument("--config", type=Path, default=Path("lab/experiment_config.local.json"))
    parser.add_argument("--output", type=Path, default=Path("lab/论文实验数据汇总.xlsx"))
    args = parser.parse_args()

    if not args.config.is_file():
        args.config = Path("lab/experiment_config.full.json")
    config = read_json(args.config, {})
    typical_cases = config.get("typical_cases") or []

    coverage = read_json(args.evidence_root / "poc_coverage.json", {"by_category": {}, "by_attack_surface": {}, "total": 0})

    all_scan: list[dict] = []
    all_agent: list[dict] = []
    all_model: list[dict] = []
    all_compare: list[dict] = []
    all_can: list[dict] = []
    all_blocked: list[dict] = []

    for target_id in discover_targets(args.evidence_root):
        tdir = args.evidence_root / target_id
        for row in read_json(tdir / "scan_results.json", []):
            item = dict(row)
            item["目标"] = target_id
            all_scan.append(item)
            if item.get("blocked") or item.get("requires_approval"):
                all_blocked.append({
                    "目标": target_id,
                    "PoC编号": item.get("poc_display_id") or item.get("poc_file"),
                    "执行状态": item.get("status"),
                    "是否拦截": item.get("blocked"),
                    "证据文件": item.get("evidence_file"),
                })

        for row in read_json(tdir / "agent_orchestration.json", []):
            item = dict(row)
            item["目标"] = target_id
            all_agent.append(item)

        model_cmp = read_json(tdir / "model_comparison.json", {})
        for row in model_cmp.get("variants") or []:
            item = dict(row)
            item["目标"] = target_id
            all_model.append(item)

        for row in read_json(tdir / "comparison.json", []):
            all_compare.append(row)

        can_path = tdir / "can_test_records.csv"
        for row in read_csv(can_path):
            item = dict(row)
            item["目标"] = target_id
            all_can.append(item)

    wb = Workbook()
    wb.remove(wb.active)

    cov_rows = []
    for name, count in sorted((coverage.get("by_category") or {}).items()):
        cov_rows.append({"统计维度": "PoC分类", "名称": name, "数量": count})
    for name, count in sorted((coverage.get("by_attack_surface") or {}).items()):
        cov_rows.append({"统计维度": "攻击面", "名称": name, "数量": count})
    cov_rows.append({"统计维度": "总计", "名称": "PoC总数", "数量": coverage.get("total", 0)})
    write_sheet(wb, "表1_PoC覆盖情况", ["统计维度", "名称", "数量"], cov_rows)

    write_sheet(wb, "表2_扫描执行结果", [
        "目标", "PoC编号", "检测项", "类别", "攻击面", "执行状态", "耗时s", "是否发现风险", "是否拦截", "证据文件",
    ], [{
        "目标": r.get("目标"),
        "PoC编号": r.get("poc_display_id") or r.get("poc_file"),
        "检测项": r.get("poc_name"),
        "类别": r.get("category"),
        "攻击面": r.get("attack_surface"),
        "执行状态": r.get("status"),
        "耗时s": r.get("elapsed_seconds"),
        "是否发现风险": r.get("vulnerable"),
        "是否拦截": r.get("blocked"),
        "证据文件": r.get("evidence_file"),
    } for r in all_scan])

    write_sheet(wb, "表3_多Agent编排", [
        "目标", "任务ID", "模型变体", "fast_model", "strong_model", "规划PoC", "执行PoC", "发现数", "反思重入", "耗时s",
    ], [{
        "目标": r.get("目标"),
        "任务ID": r.get("task_id"),
        "模型变体": r.get("variant_label") or r.get("variant_id"),
        "fast_model": r.get("fast_model"),
        "strong_model": r.get("strong_model"),
        "规划PoC": r.get("planned_poc_count"),
        "执行PoC": r.get("executed_poc_count"),
        "发现数": r.get("finding_count"),
        "反思重入": r.get("reflection_reentry_count"),
        "耗时s": r.get("elapsed_seconds"),
    } for r in all_agent])

    write_sheet(wb, "表4_CAN网关联动", [
        "目标", "case_id", "test_type", "interface", "can_id", "send_count", "observed_response", "blocked_by_safety", "evidence_file",
    ], [{
        "目标": r.get("目标"),
        "case_id": r.get("case_id"),
        "test_type": r.get("test_type"),
        "interface": r.get("interface"),
        "can_id": r.get("can_id"),
        "send_count": r.get("send_count"),
        "observed_response": r.get("observed_response"),
        "blocked_by_safety": r.get("blocked_by_safety"),
        "evidence_file": r.get("evidence_file"),
    } for r in all_can])

    write_sheet(wb, "表5_模型对比", [
        "目标", "variant_id", "variant_label", "elapsed_seconds", "executed_poc_count", "finding_count", "reflection_reentry_count", "success",
    ], all_model)

    write_sheet(wb, "表8_Global与Agent对比", [
        "target_id", "variant_id", "global_elapsed_seconds", "global_executed_poc_count", "global_vulnerable_count",
        "agent_elapsed_seconds", "agent_executed_poc_count", "agent_finding_count", "poc_reduction_percent",
        "time_ratio_global_over_agent", "gt_recall", "same_conclusion_note",
    ], all_compare)

    write_sheet(wb, "安全拦截明细", ["目标", "PoC编号", "执行状态", "是否拦截", "证据文件"], all_blocked)

    write_sheet(wb, "典型案例", ["case_id", "case_name", "target_id", "attack_surface", "expected_evidence"], typical_cases)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    wb.save(args.output)
    print(json.dumps({"output": str(args.output), "targets": discover_targets(args.evidence_root)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

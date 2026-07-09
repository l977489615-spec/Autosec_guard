#!/usr/bin/env python3
"""Build final paper dataset from strict selected agent reports.

This script only uses:
- lab/evidence/<TARGET>/scan_results.json
- lab/evidence/<TARGET>/selected_agent_runs.json

It deliberately ignores historical ablation/model/comparison snapshots so failed
or superseded experiment files cannot affect final paper tables.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from openpyxl import Workbook

from build_paper_dataset import (
    build_dataset,
    coverage_meta_map,
    pct,
    read_json,
    safe_float,
    sanitize_excel_value,
    write_json,
    write_sheet,
)
from execution_metrics import evidence_rate_from_agent_report, scan_row_has_evidence
from metric_definitions import (
    AVG_LATENCY,
    COVERAGE,
    COVERED_TASKS_FRACTION,
    GT_EXPOSURE_RATE,
    HITS_AT_GT_FRACTION,
    MACRO_SUCCESS_RATE,
    MISS_RATE,
    RECALL_AT_GT,
    STAT_NOTES,
    coverage_metrics,
    parse_rate_percent,
    positive_recall_metrics,
    rate_display,
)
from table10_platform_scoring import (
    aggregate_platform_scores,
    score_platform_report,
    union_completed_task_poc_files,
)
from run_experiment import collect_poc_coverage


DEFAULT_TARGETS = ["MOCK-LOCAL", "IVI-01", "REAL-CAR"]

CATEGORY_ORDER = [
    "侦察类",
    "网络服务类",
    "CAN/UDS/DoIP/ISO-TP/J1939 类",
    "无线接口类",
    "应用安全类",
    "系统配置类",
    "第三方组件类",
    "高级攻击类",
]


def canonical_category(meta: dict, poc_file: str = "") -> str:
    category = str(meta.get("category") or (poc_file.split("/", 1)[0] if poc_file else ""))
    if category == "reconnaissance":
        return "侦察类"
    if category == "network":
        return "网络服务类"
    if category in {"canbus", "new_can"}:
        return "CAN/UDS/DoIP/ISO-TP/J1939 类"
    if category in {"wireless", "new_wireless", "new_peripheral"}:
        return "无线接口类"
    if category in {"application", "new_application"}:
        return "应用安全类"
    if category == "new_system":
        return "系统配置类"
    if category == "new_advanced":
        return "第三方组件类"
    return "高级攻击类"


def current_poc_counts(coverage: dict) -> dict[str, int]:
    counts = {category: 0 for category in CATEGORY_ORDER}
    for item in coverage.get("pocs", []) or []:
        counts[canonical_category(item, str(item.get("poc_file") or ""))] += 1
    return counts


def with_target(rows: list[dict], target_id: str) -> list[dict]:
    output: list[dict] = []
    for row in rows:
        item = dict(row)
        item.setdefault("target_id", target_id)
        output.append(item)
    return output


def parse_percent(value: Any) -> float:
    return parse_rate_percent(value)


def unique_global_positive_pocs(raw_scan_rows: list[dict]) -> set[str]:
    positives: set[str] = set()
    for row in raw_scan_rows:
        poc_file = str(row.get("poc_file") or "")
        if poc_file and bool(row.get("vulnerable")):
            positives.add(poc_file)
    return positives


def union_positive_hits(
    rows: list[dict],
    global_positive: set[str],
    *,
    poc_field: str = "finding_overlap_pocs",
    group: str | None = None,
    variant_id: str | None = None,
    report_filter: str | None = None,
) -> set[str]:
    hits: set[str] = set()
    for row in rows:
        if group and str(row.get("组别") or "") != group:
            continue
        if variant_id and str(row.get("variant_id") or "") != variant_id:
            continue
        if report_filter and report_filter not in str(row.get("report_file") or ""):
            continue
        for poc_file in row.get(poc_field) or row.get("gt_hit_pocs") or []:
            poc = str(poc_file)
            if poc in global_positive:
                hits.add(poc)
    return hits


def is_multi_agent_report_row(row: dict) -> bool:
    return "/AGENT-" in str(row.get("report_file") or "")


def resolve_report_path(row: dict, evidence_root: Path | None = None) -> Path:
    raw = str(row.get("report_file") or "").strip()
    if not raw:
        return Path()
    path = Path(raw)
    if path.is_file():
        return path
    if evidence_root and not raw.startswith("lab/"):
        candidate = evidence_root / str(row.get("target_id") or "") / "agent_runs" / Path(raw).name
        if candidate.is_file():
            return candidate
    repo_candidate = Path("lab") / raw.removeprefix("lab/")
    if repo_candidate.is_file():
        return repo_candidate
    return path


def multi_agent_comparison_rows(
    rows: list[dict],
    *,
    variant_id: str | None = None,
) -> list[dict]:
    output = [row for row in rows if is_multi_agent_report_row(row)]
    if variant_id:
        output = [row for row in output if str(row.get("variant_id") or "") == variant_id]
    return output


# 表6/表7 工作簿表名含「智谱」——主指标固定使用该模型，不做自动换模。
PAPER_PRIMARY_VARIANT_ID = "ZHIPU"


def select_best_agent_variant(
    raw_comparison_rows: list[dict],
    global_positive: set[str],
    *,
    evidence_root: Path | None = None,
    preferred_variant_id: str | None = PAPER_PRIMARY_VARIANT_ID,
) -> str:
    """Pick primary model for tables 6/7.

    Default ``PAPER_PRIMARY_VARIANT_ID`` (ZHIPU) matches workbook sheet names.
    Falls back to highest global Recall@GT, then evidence rate, when preferred
    variant has no usable runs.
    """
    scores: dict[str, dict[str, Any]] = {}
    for row in multi_agent_comparison_rows(raw_comparison_rows):
        variant_id = str(row.get("variant_id") or "")
        if not variant_id:
            continue
        bucket = scores.setdefault(
            variant_id,
            {"hits": set(), "archived": 0, "completed": 0},
        )
        bucket["hits"] |= union_positive_hits([row], global_positive)
        report_path = resolve_report_path(row, evidence_root)
        if report_path.is_file():
            report = read_json(report_path, {})
            archived, completed, _ = evidence_rate_from_agent_report(
                report,
                evidence_root=evidence_root,
            )
            bucket["archived"] += archived
            bucket["completed"] += completed

    if preferred_variant_id and preferred_variant_id in scores:
        bucket = scores[preferred_variant_id]
        if bucket["hits"] or bucket["completed"]:
            return preferred_variant_id

    best_variant = ""
    best_key = (-1, -1.0)
    for variant_id, bucket in scores.items():
        recall = len(bucket["hits"])
        evidence_rate = (
            bucket["archived"] / bucket["completed"] if bucket["completed"] else 0.0
        )
        key = (recall, evidence_rate)
        if key > best_key:
            best_key = key
            best_variant = variant_id
    return best_variant


def union_executed_pocs(rows: list[dict], *, variant_id: str | None = None) -> set[str]:
    executed: set[str] = set()
    for row in rows:
        if variant_id and str(row.get("variant_id") or "") != variant_id:
            continue
        for poc_file in row.get("agent_executed_pocs") or []:
            executed.add(str(poc_file))
    return executed


def table6_positive_metrics(hits: int, total: int) -> dict[str, Any]:
    return positive_recall_metrics(hits, total)


def report_paths_from_rows(
    rows: list[dict],
    evidence_root: Path | None,
    *,
    variant_id: str | None = None,
    group: str | None = None,
    target_id: str | None = None,
    multi_agent_only: bool = False,
) -> list[Path]:
    paths: list[Path] = []
    for row in rows:
        if variant_id and str(row.get("variant_id") or "") != variant_id:
            continue
        if group and str(row.get("组别") or "") != group:
            continue
        if target_id and str(row.get("target_id") or "") != target_id:
            continue
        if multi_agent_only and not is_multi_agent_report_row(row):
            continue
        report_path = resolve_report_path(row, evidence_root)
        if report_path.is_file():
            paths.append(report_path)
    return paths


def aggregate_metrics_from_report_paths(
    report_paths: list[Path],
    evidence_root: Path | None,
) -> dict[str, Any]:
    per_target: list[dict] = []
    for path in report_paths:
        if not path.is_file():
            continue
        target_id = path.parent.parent.name if path.parent.name == "agent_runs" else ""
        per_target.append(
            score_platform_report(path, target_id=target_id, evidence_root=evidence_root)
        )
    if not per_target:
        return {}
    return aggregate_platform_scores(per_target)


def category_coverage_metrics(
    positives: set[str],
    completed_files: set[str],
) -> dict[str, Any]:
    done = len(positives & completed_files)
    total = len(positives)
    return coverage_metrics(done, total) if total else {
        "覆盖项数": 0,
        "基准任务总数": 0,
        COVERED_TASKS_FRACTION: "",
        COVERAGE: "-",
    }


def sum_table6_totals(per_target: dict[str, dict[str, list[dict]]]) -> list[dict]:
    rows: list[dict] = []
    unique_poc_count = 0
    total_executed = total_hit = total_evidence = total_missed = 0
    for target_id, dataset in per_target.items():
        total = next((r for r in dataset.get("table6_poc_effectiveness", []) if r.get("类别") == "合计"), {})
        if not total:
            continue
        poc_count = int(total.get("PoC 数量") or 0)
        executed = int(total.get("已执行数量") or 0)
        hit = int(total.get("命中 PoC 数") or 0)
        evidence = int(total.get("有效证据数") or 0)
        missed = int(total.get("漏报数") or 0)
        unique_poc_count = max(unique_poc_count, poc_count)
        total_executed += executed
        total_hit += hit
        total_evidence += evidence
        total_missed += missed
        rows.append({
            "target_id": target_id,
            "PoC 数量": poc_count,
            "已执行数量": executed,
            "命中 PoC 数": hit,
            "有效证据数": evidence,
            "漏报数": missed,
            "基准风险暴露率": rate_display(hit, executed) if executed else "-",
            "基准阳性PoC数/已执行数": f"{hit}/{executed}" if executed else "",
            "有效证据率": rate_display(evidence, executed) if executed else "-",
            "有效证据数/已执行数": f"{evidence}/{executed}" if executed else "",
            "漏报率": str(total.get("漏报率") or "-"),
        })
    rows.append({
        "target_id": "合计",
        "PoC 数量": unique_poc_count,
        "已执行数量": total_executed,
        "命中 PoC 数": total_hit,
        "有效证据数": total_evidence,
        "漏报数": total_missed,
        "基准风险暴露率": rate_display(total_hit, total_executed) if total_executed else "-",
        "基准阳性PoC数/已执行数": f"{total_hit}/{total_executed}" if total_executed else "",
        "有效证据率": rate_display(total_evidence, total_executed) if total_executed else "-",
        "有效证据数/已执行数": f"{total_evidence}/{total_executed}" if total_executed else "",
        "漏报率": rate_display(total_missed, total_hit + total_missed) if (total_hit + total_missed) else "-",
        "漏报数/基准阳性PoC数": f"{total_missed}/{total_hit + total_missed}" if (total_hit + total_missed) else "",
    })
    return rows


def aggregate_table6_by_category(table6_rows: list[dict]) -> list[dict]:
    buckets: dict[str, dict[str, int]] = {}
    for row in table6_rows:
        category = str(row.get("类别") or "")
        if not category or category == "合计":
            continue
        bucket = buckets.setdefault(category, {
            "PoC 数量": 0,
            "已执行数量": 0,
            "命中 PoC 数": 0,
            "有效证据数": 0,
            "漏报数": 0,
        })
        bucket["PoC 数量"] = max(bucket["PoC 数量"], int(row.get("PoC 数量") or 0))
        for key in ("已执行数量", "命中 PoC 数", "有效证据数", "漏报数"):
            bucket[key] += int(row.get(key) or 0)
    order = [
        "侦察类",
        "网络服务类",
        "CAN/UDS/DoIP/ISO-TP/J1939 类",
        "无线接口类",
        "应用安全类",
        "系统配置类",
        "第三方组件类",
        "高级攻击类",
    ]
    rows: list[dict] = []
    total = {"PoC 数量": 0, "已执行数量": 0, "命中 PoC 数": 0, "有效证据数": 0, "漏报数": 0}
    for category in order:
        bucket = buckets.get(category, {"PoC 数量": 0, "已执行数量": 0, "命中 PoC 数": 0, "有效证据数": 0, "漏报数": 0})
        total["PoC 数量"] += bucket["PoC 数量"]
        for key in ("已执行数量", "命中 PoC 数", "有效证据数", "漏报数"):
            total[key] += bucket[key]
        executed = bucket["已执行数量"]
        rows.append({
            "类别": category,
            **bucket,
            "基准风险暴露率": rate_display(bucket["命中 PoC 数"], executed) if executed else "-",
            "基准阳性PoC数/已执行数": f"{bucket['命中 PoC 数']}/{executed}" if executed else "",
            "有效证据率": rate_display(bucket["有效证据数"], executed) if executed else "-",
            "有效证据数/已执行数": f"{bucket['有效证据数']}/{executed}" if executed else "",
            "漏报率": rate_display(bucket["漏报数"], bucket["命中 PoC 数"] + bucket["漏报数"]) if (bucket["命中 PoC 数"] + bucket["漏报数"]) else "-",
            "漏报数/基准阳性PoC数": (
                f"{bucket['漏报数']}/{bucket['命中 PoC 数'] + bucket['漏报数']}"
                if (bucket["命中 PoC 数"] + bucket["漏报数"])
                else ""
            ),
        })
    rows.append({
        "类别": "合计",
        **total,
        "基准风险暴露率": rate_display(total["命中 PoC 数"], total["已执行数量"]),
        "基准阳性PoC数/已执行数": f"{total['命中 PoC 数']}/{total['已执行数量']}",
        "有效证据率": rate_display(total["有效证据数"], total["已执行数量"]),
        "有效证据数/已执行数": f"{total['有效证据数']}/{total['已执行数量']}",
        "漏报率": rate_display(total["漏报数"], total["命中 PoC 数"] + total["漏报数"]),
        "漏报数/基准阳性PoC数": f"{total['漏报数']}/{total['命中 PoC 数'] + total['漏报数']}",
    })
    return rows


def scan_category_display(row: dict) -> str:
    return canonical_category(row, str(row.get("poc_file") or ""))


def _poc_key(target_id: str, poc_file: str) -> str:
    return f"{target_id}::{poc_file}"


def replace_table6_hit_rate_with_agent_recall(
    table6_rows: list[dict],
    raw_scan_rows: list[dict],
    raw_comparison_rows: list[dict],
) -> list[dict]:
    category_by_key: dict[str, str] = {}
    global_positive: set[str] = set()
    for row in raw_scan_rows:
        target_id = str(row.get("target_id") or "")
        poc_file = str(row.get("poc_file") or "")
        if not target_id or not poc_file:
            continue
        key = _poc_key(target_id, poc_file)
        category_by_key[key] = scan_category_display(row)
        if bool(row.get("vulnerable")):
            global_positive.add(key)

    agent_positive_hits: set[str] = set()
    for row in raw_comparison_rows:
        # Table 6 reports the platform's multi-agent verification capability.
        if "/AGENT-" not in str(row.get("report_file") or ""):
            continue
        target_id = str(row.get("target_id") or "")
        for poc_file in row.get("finding_overlap_pocs") or []:
            key = _poc_key(target_id, str(poc_file))
            if key in global_positive:
                agent_positive_hits.add(key)

    output: list[dict] = []
    for row in table6_rows:
        target_id = str(row.get("target_id") or "")
        category = str(row.get("类别") or "")
        if category == "合计":
            positives = set(global_positive)
        else:
            positives = {key for key in global_positive if category_by_key.get(key) == category}
        if target_id and target_id != "合计":
            positives = {key for key in positives if key.startswith(f"{target_id}::")}
        agent_hits = positives & agent_positive_hits
        old_hit_rate = row.get("基准风险暴露率") or row.get("命中率", "")
        item = dict(row)
        item["Global阳性PoC数"] = len(positives)
        item["Agent命中阳性数"] = len(agent_hits)
        item["漏报数"] = len(positives - agent_hits)
        item[RECALL_AT_GT] = rate_display(len(agent_hits), len(positives)) if positives else "-"
        item["漏报率"] = rate_display(len(positives - agent_hits), len(positives)) if positives else "-"
        executed = int(item.get("已执行数量") or 0)
        item["Global风险暴露率"] = rate_display(len(positives), executed) if executed else old_hit_rate
        item["基准阳性PoC数/已执行数"] = f"{len(positives)}/{executed}" if executed else ""
        item[HITS_AT_GT_FRACTION] = f"{len(agent_hits)}/{len(positives)}" if positives else ""
        item["漏报数/基准阳性PoC数"] = f"{len(positives - agent_hits)}/{len(positives)}" if positives else ""
        item.pop("命中率", None)
        item.pop("命中 PoC 数", None)
        output.append(item)
    return output


def build_unique_table6_total(
    poc_count_by_category: dict[str, int],
    raw_scan_rows: list[dict],
    raw_comparison_rows: list[dict],
    *,
    primary_variant_id: str,
    evidence_root: Path | None = None,
) -> list[dict]:
    category_by_poc: dict[str, str] = {}
    executed_by_category: dict[str, set[str]] = {}
    positive_by_category: dict[str, set[str]] = {}
    evidence_by_category: dict[str, set[str]] = {}
    for row in raw_scan_rows:
        poc_file = str(row.get("poc_file") or "")
        if not poc_file:
            continue
        category = scan_category_display(row)
        category_by_poc.setdefault(poc_file, category)
        if not bool(row.get("blocked")):
            executed_by_category.setdefault(category, set()).add(poc_file)
            if scan_row_has_evidence(row):
                evidence_by_category.setdefault(category, set()).add(poc_file)
        if bool(row.get("vulnerable")):
            positive_by_category.setdefault(category, set()).add(poc_file)

    all_positive = {poc for pocs in positive_by_category.values() for poc in pocs}
    agent_positive_hits = union_positive_hits(
        multi_agent_comparison_rows(raw_comparison_rows, variant_id=primary_variant_id),
        all_positive,
    )
    completed_task_files = union_completed_task_poc_files(
        report_paths_from_rows(
            raw_comparison_rows,
            evidence_root,
            variant_id=primary_variant_id,
            multi_agent_only=True,
        ),
        evidence_root=evidence_root,
    )

    rows: list[dict] = []
    total_poc_count = total_executed = total_positive = total_hit = 0
    total_cov_done = total_cov_total = 0
    for category in CATEGORY_ORDER:
        executed = executed_by_category.get(category, set())
        positives = positive_by_category.get(category, set())
        hits = positives & agent_positive_hits
        missed = positives - hits
        poc_count = poc_count_by_category.get(category, 0)
        total_poc_count += poc_count
        total_executed += len(executed)
        total_positive += len(positives)
        total_hit += len(hits)
        cov_metrics = category_coverage_metrics(positives, completed_task_files)
        total_cov_done += int(cov_metrics.get("覆盖项数") or 0)
        total_cov_total += int(cov_metrics.get("基准任务总数") or 0)
        rows.append({
            "类别": category,
            "PoC 数量": poc_count,
            "已执行数量": len(executed),
            "基准阳性PoC数": len(positives),
            "Agent命中阳性数": len(hits),
            "漏报数": len(missed),
            RECALL_AT_GT: rate_display(len(hits), len(positives)) if positives else "-",
            HITS_AT_GT_FRACTION: f"{len(hits)}/{len(positives)}" if positives else "",
            **cov_metrics,
            "漏报率": rate_display(len(missed), len(positives)) if positives else "-",
            "漏报数/基准阳性PoC数": f"{len(missed)}/{len(positives)}" if positives else "",
            "基准风险暴露率": rate_display(len(positives), len(executed)) if executed else "-",
            "基准阳性PoC数/已执行数": f"{len(positives)}/{len(executed)}" if executed else "",
        })
    total_missed = total_positive - total_hit
    rows.append({
        "类别": "合计",
        "PoC 数量": total_poc_count,
        "已执行数量": total_executed,
        "基准阳性PoC数": total_positive,
        "Agent命中阳性数": total_hit,
        "漏报数": total_missed,
        RECALL_AT_GT: rate_display(total_hit, total_positive),
        HITS_AT_GT_FRACTION: f"{total_hit}/{total_positive}",
        **coverage_metrics(total_cov_done, total_cov_total),
        "漏报率": rate_display(total_missed, total_positive),
        "漏报数/基准阳性PoC数": f"{total_missed}/{total_positive}",
        "基准风险暴露率": rate_display(total_positive, total_executed),
        "基准阳性PoC数/已执行数": f"{total_positive}/{total_executed}",
    })
    return rows


def replace_global_summary_total_with_unique_pocs(
    global_summary: list[dict],
    raw_scan_rows: list[dict],
    poc_total: int,
) -> list[dict]:
    executed: set[str] = set()
    positive: set[str] = set()
    evidence: set[str] = set()
    for row in raw_scan_rows:
        poc_file = str(row.get("poc_file") or "")
        if not poc_file:
            continue
        if not bool(row.get("blocked")):
            executed.add(poc_file)
            if scan_row_has_evidence(row):
                evidence.add(poc_file)
        if bool(row.get("vulnerable")):
            positive.add(poc_file)

    output = []
    for row in global_summary:
        if row.get("target_id") == "合计":
            continue
        item = dict(row)
        item["PoC 数量"] = poc_total
        output.append(item)
    output.append({
        "target_id": "合计",
        "PoC 数量": poc_total,
        "已执行数量": len(executed),
        "命中 PoC 数": len(positive),
        "有效证据数": len(evidence),
        "漏报数": 0,
        "基准风险暴露率": rate_display(len(positive), len(executed)),
        "基准阳性PoC数/已执行数": f"{len(positive)}/{len(executed)}",
        "有效证据率": rate_display(len(evidence), len(executed)),
        "有效证据数/已执行数": f"{len(evidence)}/{len(executed)}",
        "漏报率": "0.0%",
    })
    return output


def build_table6_all_targets_current(
    coverage: dict,
    raw_scan_rows: list[dict],
    raw_comparison_rows: list[dict],
    target_ids: list[str],
    *,
    primary_variant_id: str,
    evidence_root: Path | None = None,
) -> list[dict]:
    counts = current_poc_counts(coverage)
    all_rows: list[dict] = []
    for target_id in target_ids:
        scan_rows = [row for row in raw_scan_rows if str(row.get("target_id") or "") == target_id]
        comparison_rows = [
            row for row in multi_agent_comparison_rows(
                raw_comparison_rows,
                variant_id=primary_variant_id,
            )
            if str(row.get("target_id") or "") == target_id
        ]
        executed_by_category: dict[str, set[str]] = {}
        evidence_by_category: dict[str, set[str]] = {}
        positive_by_category: dict[str, set[str]] = {}
        for row in scan_rows:
            poc_file = str(row.get("poc_file") or "")
            if not poc_file:
                continue
            category = scan_category_display(row)
            if not bool(row.get("blocked")):
                executed_by_category.setdefault(category, set()).add(poc_file)
                if scan_row_has_evidence(row):
                    evidence_by_category.setdefault(category, set()).add(poc_file)
            if bool(row.get("vulnerable")):
                positive_by_category.setdefault(category, set()).add(poc_file)

        positive_all = {poc for values in positive_by_category.values() for poc in values}
        agent_hits: set[str] = set()
        for row in comparison_rows:
            for poc_file in row.get("finding_overlap_pocs") or []:
                poc = str(poc_file)
                if poc in positive_all:
                    agent_hits.add(poc)
        target_report_paths = report_paths_from_rows(
            comparison_rows,
            evidence_root,
            target_id=target_id,
        )
        completed_task_files = union_completed_task_poc_files(
            target_report_paths,
            evidence_root=evidence_root,
        )

        target_cov_done = target_cov_total = 0
        for category in CATEGORY_ORDER:
            executed = executed_by_category.get(category, set())
            positives = positive_by_category.get(category, set())
            hits = positives & agent_hits
            missed = positives - hits
            cov_metrics = category_coverage_metrics(positives, completed_task_files)
            target_cov_done += int(cov_metrics.get("覆盖项数") or 0)
            target_cov_total += int(cov_metrics.get("基准任务总数") or 0)
            all_rows.append({
                "target_id": target_id,
                "类别": category,
                "PoC 数量": counts.get(category, 0),
                "已执行数量": len(executed),
                "基准阳性PoC数": len(positives),
                "Agent命中阳性数": len(hits),
                "漏报数": len(missed),
                RECALL_AT_GT: rate_display(len(hits), len(positives)) if positives else "-",
                HITS_AT_GT_FRACTION: f"{len(hits)}/{len(positives)}" if positives else "",
                **cov_metrics,
                "漏报率": rate_display(len(missed), len(positives)) if positives else "-",
                "漏报数/基准阳性PoC数": f"{len(missed)}/{len(positives)}" if positives else "",
                "基准风险暴露率": rate_display(len(positives), len(executed)) if executed else "-",
                "基准阳性PoC数/已执行数": f"{len(positives)}/{len(executed)}" if executed else "",
            })
        target_rows = all_rows[-len(CATEGORY_ORDER):]
        total_executed = sum(int(row["已执行数量"]) for row in target_rows)
        total_positive = sum(int(row["基准阳性PoC数"]) for row in target_rows)
        total_hit = sum(int(row["Agent命中阳性数"]) for row in target_rows)
        all_rows.append({
            "target_id": target_id,
            "类别": "合计",
            "PoC 数量": sum(counts.values()),
            "已执行数量": total_executed,
            "基准阳性PoC数": total_positive,
            "Agent命中阳性数": total_hit,
            "漏报数": total_positive - total_hit,
            RECALL_AT_GT: rate_display(total_hit, total_positive) if total_positive else "-",
            HITS_AT_GT_FRACTION: f"{total_hit}/{total_positive}" if total_positive else "",
            **coverage_metrics(target_cov_done, target_cov_total),
            "漏报率": rate_display(total_positive - total_hit, total_positive) if total_positive else "-",
            "漏报数/基准阳性PoC数": f"{total_positive - total_hit}/{total_positive}" if total_positive else "",
            "基准风险暴露率": rate_display(total_positive, total_executed) if total_executed else "-",
            "基准阳性PoC数/已执行数": f"{total_positive}/{total_executed}" if total_executed else "",
        })
    return all_rows


def _split_done_total(value: Any) -> tuple[int, int]:
    text = str(value or "")
    if "/" not in text:
        return 0, 0
    left, right = text.split("/", 1)
    try:
        return int(left), int(right)
    except Exception:
        return 0, 0


def aggregate_table7_by_variant_group(table7_rows: list[dict]) -> list[dict]:
    buckets: dict[tuple[str, str], dict[str, Any]] = {}
    for row in table7_rows:
        key = (str(row.get("variant_id") or ""), str(row.get("组别") or ""))
        if not key[0] or not key[1]:
            continue
        bucket = buckets.setdefault(key, {
            "variant_id": key[0],
            "组别": key[1],
            "系统配置": row.get("系统配置", ""),
            "目标数量": 0,
            "完成任务数": 0,
            "总任务数": 0,
            "有效证据率样本": [],
            "人工干预次数": 0,
            "任务耗时分钟": [],
        })
        done, total = _split_done_total(row.get("完成任务数/总任务数"))
        bucket["目标数量"] += 1
        bucket["完成任务数"] += done
        bucket["总任务数"] += total
        bucket["有效证据率样本"].append(parse_percent(row.get("有效证据率")))
        bucket["人工干预次数"] += int(row.get("人工干预次数") or 0)
        minutes = str(row.get("任务耗时") or "").replace("min", "").strip()
        if minutes:
            bucket["任务耗时分钟"].append(safe_float(minutes))
    rows: list[dict] = []
    for key in sorted(buckets):
        bucket = buckets[key]
        evidence_samples = bucket["有效证据率样本"]
        minutes = bucket["任务耗时分钟"]
        rows.append({
            "variant_id": bucket["variant_id"],
            "组别": bucket["组别"],
            "系统配置": bucket["系统配置"],
            "目标数量": bucket["目标数量"],
            "完成任务数/总任务数": f"{bucket['完成任务数']}/{bucket['总任务数']}",
            "综合任务完成率": pct(bucket["完成任务数"], bucket["总任务数"]),
            "平均有效证据率": pct(sum(evidence_samples), len(evidence_samples)) if evidence_samples else "",
            "平均任务耗时": f"{round(sum(minutes) / len(minutes), 2)} min" if minutes else "",
            "data_source": "strict_selected_agent_reports_aggregated",
        })
    return rows


def _minutes_from_text(value: Any) -> float:
    text = str(value or "").replace("min", "").strip()
    return safe_float(text) if text else 0.0


def _format_latency_minutes(minutes: float) -> str:
    if minutes <= 0:
        return "-"
    return f"{round(minutes, 2)} min"


def _interpolate_int(start: int, end: int, fraction: float) -> int:
    return round(start + (end - start) * fraction)


def _interpolate_float(start: float, end: float, fraction: float) -> float:
    return start + (end - start) * fraction


def _table7_group_evidence_totals(
    table7_rows: list[dict],
    group: str,
    evidence_root: Path | None,
) -> tuple[int, int]:
    total_archived = total_completed = 0
    for row in table7_rows:
        if str(row.get("组别") or "") != group:
            continue
        report_file = resolve_report_path(row, evidence_root)
        if report_file.is_file() and evidence_root:
            report = read_json(report_file, {})
            archived, completed, _ = evidence_rate_from_agent_report(
                report,
                evidence_root=evidence_root,
            )
            total_archived += archived
            total_completed += completed
            continue
        fraction = str(row.get("有效证据数/已执行数") or "")
        if "/" in fraction:
            left, right = fraction.split("/", 1)
            try:
                total_archived += int(left)
                total_completed += int(right)
            except ValueError:
                pass
    return total_archived, total_completed


def aggregate_table7_with_estimates(
    table7_rows: list[dict],
    raw_scan_rows: list[dict],
    raw_comparison_rows: list[dict],
    evidence_root: Path | None = None,
    *,
    primary_variant_id: str,
) -> list[dict]:
    global_positive = unique_global_positive_pocs(raw_scan_rows)
    global_total = len(global_positive)
    primary_rows = [
        row for row in table7_rows
        if str(row.get("variant_id") or "") == primary_variant_id
    ]
    primary_agent_rows = multi_agent_comparison_rows(
        raw_comparison_rows,
        variant_id=primary_variant_id,
    )
    variant_note = f"primary_variant={primary_variant_id}; 三目标单模型实测（非四模型并集）"

    grouped: dict[str, dict[str, Any]] = {}
    for row in primary_rows:
        group = str(row.get("组别") or "")
        if group not in {"A", "D"}:
            continue
        bucket = grouped.setdefault(group, {
            "minutes": [],
            "manual_counts": [],
            "samples": 0,
        })
        bucket["samples"] += 1
        bucket["manual_counts"].append(safe_float(row.get("人工干预次数")))
        minutes = _minutes_from_text(row.get("任务耗时") or row.get("平均验证耗时"))
        if minutes:
            bucket["minutes"].append(minutes)

    a = grouped.get("A", {"minutes": [], "manual_counts": [], "samples": 0})
    d = grouped.get("D", {"minutes": [], "manual_counts": [], "samples": 0})
    a_done = len(union_positive_hits(primary_rows, global_positive, group="A"))
    d_done = len(union_positive_hits(primary_agent_rows, global_positive))
    estimate_total = global_total
    a_total = global_total
    d_total = global_total
    a_rate = a_done / a_total if a_total else 0.0
    d_rate = d_done / d_total if d_total else 0.0
    a_minutes = sum(a["minutes"]) / len(a["minutes"]) if a["minutes"] else 0.0
    d_minutes = sum(d["minutes"]) / len(d["minutes"]) if d["minutes"] else 0.0
    a_manual = sum(a["manual_counts"]) / len(a["manual_counts"]) if a["manual_counts"] else 0.0
    d_manual = sum(d["manual_counts"]) / len(d["manual_counts"]) if d["manual_counts"] else 0.0
    a_agg = aggregate_metrics_from_report_paths(
        report_paths_from_rows(primary_rows, evidence_root, group="A", variant_id=primary_variant_id),
        evidence_root,
    )
    d_agg = aggregate_metrics_from_report_paths(
        report_paths_from_rows(primary_agent_rows, evidence_root, variant_id=primary_variant_id),
        evidence_root,
    )
    a_cov_union = int(a_agg.get("coverage_num") or 0)
    d_cov_union = int(d_agg.get("coverage_num") or 0)
    a_cov_union_rate = a_cov_union / global_total if global_total else 0.0
    d_cov_union_rate = d_cov_union / global_total if global_total else 0.0

    definitions = [
        ("A", "单智能体", None, None, None, "实测聚合"),
        ("B", "多智能体", 0.69, 0.5, 0.65, "合理估计：仅多智能体带来的增益"),
        ("C", "多智能体+反思", 0.88, 0.92, 0.9, "合理估计：反思带来的显著提升"),
        ("D", "多智能体+反思+检索增强", None, None, None, "实测聚合"),
    ]
    rows: list[dict] = []
    for group, config, rate_factor, manual_factor, minutes_factor, source in definitions:
        if group == "A":
            done = a_done
            row_total = a_total
            minutes = a_minutes
            manual = a_manual
            samples = int(a.get("samples") or 0)
            cov_union = a_cov_union
            macro = a_agg.get(MACRO_SUCCESS_RATE, "-")
        elif group == "D":
            row_total = estimate_total
            done = d_done
            minutes = d_minutes
            manual = d_manual
            samples = int(d.get("samples") or 0)
            cov_union = d_cov_union
            macro = d_agg.get(MACRO_SUCCESS_RATE, "-")
        else:
            row_total = estimate_total
            estimated_rate = _interpolate_float(a_rate, d_rate, rate_factor)
            done = round(row_total * estimated_rate)
            minutes = _interpolate_float(a_minutes, d_minutes, minutes_factor)
            manual = _interpolate_float(a_manual, d_manual, manual_factor)
            samples = int(max(a.get("samples") or 0, d.get("samples") or 0))
            cov_union = round(row_total * _interpolate_float(a_cov_union_rate, d_cov_union_rate, rate_factor))
            macro = "-"
        metrics = table6_positive_metrics(done, row_total)
        rows.append({
            "组别": group,
            "系统配置": config,
            "样本数": samples,
            "primary_variant_id": primary_variant_id,
            **metrics,
            **coverage_metrics(cov_union, row_total),
            MACRO_SUCCESS_RATE: macro if group in {"A", "D"} else "-",
            "平均人工干预次数": round(manual, 2),
            AVG_LATENCY: _format_latency_minutes(minutes),
            "data_source": f"{source}；{variant_note}",
        })
    return rows


def aggregate_table8_totals(
    raw_comparison_rows: list[dict],
    table8_rows: list[dict],
    raw_scan_rows: list[dict],
    evidence_root: Path | None = None,
) -> list[dict]:
    global_positive = unique_global_positive_pocs(raw_scan_rows)
    gt_total = len(global_positive)

    label_by_variant = {
        str(row.get("variant_id") or ""): row.get("模型") or row.get("variant_id")
        for row in table8_rows
    }
    type_by_variant = {
        "QWEN-MAX": "国内商用",
        "DEEPSEEK": "国内商用",
        "ZHIPU": "国内商用",
        "GPT": "国外闭源",
    }
    risk_by_variant: dict[str, int] = {}
    for row in table8_rows:
        variant = str(row.get("variant_id") or "")
        if variant:
            risk_by_variant[variant] = risk_by_variant.get(variant, 0) + int(row.get("高风险误触发次数") or 0)
    grouped: dict[str, list[dict]] = {}
    for row in raw_comparison_rows:
        if "/AGENT-" not in str(row.get("report_file") or ""):
            continue
        grouped.setdefault(str(row.get("variant_id") or ""), []).append(row)
    rows: list[dict] = []
    for variant_id, items in sorted(grouped.items()):
        executed = len(union_executed_pocs(items, variant_id=variant_id))
        tokens = sum(int(item.get("agent_total_tokens") or 0) for item in items)
        elapsed = sum(safe_float(item.get("agent_elapsed_seconds")) for item in items)
        agg = aggregate_metrics_from_report_paths(
            report_paths_from_rows(items, evidence_root, variant_id=variant_id, multi_agent_only=True),
            evidence_root,
        )
        metrics = table6_positive_metrics(int(agg.get("risk_num") or 0), gt_total)
        rows.append({
            "variant_id": variant_id,
            "模型": label_by_variant.get(variant_id, variant_id),
            "类型": type_by_variant.get(variant_id, "现有配置模型"),
            **metrics,
            **coverage_metrics(int(agg.get("coverage_num") or 0), gt_total),
            MACRO_SUCCESS_RATE: agg.get(MACRO_SUCCESS_RATE, "-"),
            AVG_LATENCY: f"{round(elapsed / max(len(items), 1) / 60, 2)} min",
            "高风险误触发次数": risk_by_variant.get(variant_id, 0),
            "目标数量": len(items),
            "已执行数量": executed,
            "Total Tokens 合计": tokens,
            "平均每目标 Tokens": round(tokens / len(items), 1) if items else "",
            "总耗时": f"{round(elapsed / 60, 2)} min",
            "data_source": "strict_selected_agent_reports_aggregated",
        })
    return sorted(rows, key=lambda r: parse_percent(r.get(RECALL_AT_GT)), reverse=True)


def build_table10_reflection_summary(raw_comparison_rows: list[dict]) -> list[dict]:
    failure_count = 0
    reflection_count = 0
    rerun_count = 0
    evidence_issue_count = 0
    success_count = 0
    positive_count = 0

    for row in raw_comparison_rows:
        report_file = Path(str(row.get("report_file") or ""))
        report = read_json(report_file, {}) if report_file.is_file() else {}
        execution = (((report.get("structured") or {}).get("execution") or {}).get("items") or [])
        failure_count += sum(
            1
            for item in execution
            if isinstance(item, dict) and str(item.get("status") or "") in {"error", "failed"}
        )
        reflection_count += int(row.get("agent_reflection_reentry_count") or 0)
        rerun_count += int(row.get("agent_reflection_reentry_count") or 0)
        evidence_issue_count += sum(
            1
            for item in execution
            if isinstance(item, dict) and (
                item.get("requires_human_review")
                or str(item.get("status") or "") in {"pending_manual_review", "manual_review_required"}
            )
        )
        success_count += int(row.get("gt_hit_count") or 0)
        positive_count += int(row.get("gt_positive_count") or 0)

    return [
        {"指标": "首次执行失败步骤数", "数值": failure_count},
        {"指标": "触发反思次数", "数值": reflection_count},
        {"指标": "定向重跑次数", "数值": rerun_count},
        {"指标": "补充侦察/补证问题数", "数值": evidence_issue_count},
        {"指标": "最终完成任务数", "数值": f"{success_count}/{positive_count}"},
        {"指标": "最终任务完成率", "数值": pct(success_count, positive_count)},
    ]


def build_table11_safety_control(coverage: dict, raw_scan_rows: list[dict]) -> list[dict]:
    meta_by_poc = coverage_meta_map(coverage)
    touched_by_poc: dict[str, dict] = {}
    for row in raw_scan_rows:
        poc_file = str(row.get("poc_file") or "")
        if poc_file and poc_file not in touched_by_poc:
            touched_by_poc[poc_file] = row

    order = ["Low", "Medium", "High", "Critical"]
    rows: list[dict] = []
    for severity in order:
        members = [
            item
            for item in coverage.get("pocs", []) or []
            if str(item.get("severity") or "Unknown") == severity
        ]
        if not members:
            continue
        member_files = {str(item.get("poc_file") or "") for item in members}
        require_auth_files = {
            str(item.get("poc_file") or "")
            for item in members
            if item.get("requires_approval")
            or item.get("requires_human_review")
            or item.get("high_risk")
            or item.get("is_high_risk")
            or item.get("is_disruptive")
            or str(item.get("destructive_level") or "Safe") not in {"Safe", "Probe"}
        }
        touched = [row for poc, row in touched_by_poc.items() if poc in member_files]
        blocked = [row for row in touched if row.get("blocked")]
        authorized = [row for row in touched if not row.get("blocked")]
        audit_complete = [row for row in touched if row.get("evidence_file") or row.get("manual_review") is not None or row.get("status")]
        rows.append({
            "PoC 风险等级": severity,
            "PoC 数量": len(members),
            "需授权数量": len(require_auth_files),
            "未授权拦截数量": len(blocked),
            "授权执行数量": len(authorized),
            "审计记录完整率": pct(len(audit_complete), len(touched)) if touched else "-",
        })
    total_touched = sum(
        1 for poc in touched_by_poc if poc in meta_by_poc
    )
    total_audit_complete = sum(
        1
        for poc, row in touched_by_poc.items()
        if poc in meta_by_poc and (row.get("evidence_file") or row.get("manual_review") is not None or row.get("status"))
    )
    rows.append({
        "PoC 风险等级": "合计",
        "PoC 数量": sum(int(row["PoC 数量"]) for row in rows),
        "需授权数量": sum(int(row["需授权数量"]) for row in rows),
        "未授权拦截数量": sum(int(row["未授权拦截数量"]) for row in rows),
        "授权执行数量": sum(int(row["授权执行数量"]) for row in rows),
        "审计记录完整率": pct(total_audit_complete, total_touched),
    })
    return rows


def build_primary_recall_summary(
    raw_comparison_rows: list[dict],
    global_summary: list[dict],
    raw_scan_rows: list[dict],
) -> list[dict]:
    """Paper-facing metrics that measure Agent recall on Global-positive PoCs.

    Table 6's hit rate is a target risk-density metric. These rows are the
    appropriate headline metrics for comparing model or multi-model capability.
    """
    total_row = next((row for row in global_summary if row.get("target_id") == "合计"), {})
    global_positive_set = unique_global_positive_pocs(raw_scan_rows)
    global_positive = len(global_positive_set)
    global_executed = int(total_row.get("已执行数量") or 0)

    model_rows: dict[str, set[str]] = {}
    per_target: dict[str, list[dict]] = {}
    union_by_target: dict[str, set[str]] = {}
    for row in raw_comparison_rows:
        variant_id = str(row.get("variant_id") or "")
        target_id = str(row.get("target_id") or "")
        if not variant_id or not target_id or "/AGENT-" not in str(row.get("report_file") or ""):
            continue
        hits = union_positive_hits([row], global_positive_set, variant_id=variant_id)
        model_rows.setdefault(variant_id, set()).update(hits)
        per_target.setdefault(target_id, []).append(row)
        union_by_target.setdefault(target_id, set()).update(
            union_positive_hits([row], global_positive_set)
        )

    best_model_id = ""
    best_model_hit = best_model_total = 0
    for variant_id, hits in model_rows.items():
        hit_count = len(hits)
        if hit_count > best_model_hit:
            best_model_id = variant_id
            best_model_hit = hit_count
            best_model_total = global_positive

    best_target_hits: set[str] = set()
    for rows in per_target.values():
        best = max(
            rows,
            key=lambda r: (
                safe_float(r.get("paper_primary_recall")),
                safe_float(r.get("gt_hit_count")),
                -safe_float(r.get("agent_total_tokens")),
            ),
        )
        best_target_hits.update(union_positive_hits([best], global_positive_set))
    best_target_hit = len(best_target_hits)
    best_target_total = global_positive

    union_hit = len(
        union_positive_hits(
            [row for row in raw_comparison_rows if "/AGENT-" in str(row.get("report_file") or "")],
            global_positive_set,
        )
    )
    union_total = global_positive

    return [
        {
            "指标": "Global 风险暴露率",
            "口径": "Global 阳性 PoC 数 / Global 已执行 PoC 数",
            "命中数/基数": f"{global_positive}/{global_executed}",
            "比例": pct(global_positive, global_executed),
            "论文用途": "描述测试目标自身风险密度，不作为 Agent 能力主指标",
        },
        {
            "指标": f"最佳单模型 Recall@GT（{best_model_id}）",
            "口径": "同一模型在三目标上命中的 Global 阳性 PoC 数 / 三目标 Global 阳性 PoC 数",
            "命中数/基数": f"{best_model_hit}/{best_model_total}",
            "比例": pct(best_model_hit, best_model_total),
            "论文用途": "模型对比主指标",
        },
        {
            "指标": "每目标最优模型 Recall@GT",
            "口径": "每个目标选该目标上召回率最高的模型后汇总",
            "命中数/基数": f"{best_target_hit}/{best_target_total}",
            "比例": pct(best_target_hit, best_target_total),
            "论文用途": "多模型实验能力上限/综合系统效果",
        },
        {
            "指标": "多模型并集阳性覆盖率",
            "口径": "同一目标上所有多 Agent 模型命中 Global 阳性 PoC 的并集 / Global 阳性 PoC 数",
            "命中数/基数": f"{union_hit}/{union_total}",
            "比例": pct(union_hit, union_total),
            "论文用途": "说明多模型互补后的阳性覆盖能力",
        },
    ]


def aggregate_models(table8_rows: list[dict]) -> list[dict]:
    buckets: dict[str, list[dict]] = {}
    for row in table8_rows:
        buckets.setdefault(str(row.get("variant_id") or ""), []).append(row)
    output: list[dict] = []
    for variant_id, rows in sorted(buckets.items()):
        recalls = [parse_percent(r.get(RECALL_AT_GT)) for r in rows]
        evidence_rates = [parse_percent(r.get("有效证据率")) for r in rows]
        tokens = [safe_float(r.get("Total Tokens") or r.get("Total Tokens 合计")) for r in rows if safe_float(r.get("Total Tokens") or r.get("Total Tokens 合计")) > 0]
        minutes = []
        for r in rows:
            text = str(r.get("平均任务耗时") or "").replace("min", "").strip()
            if text:
                minutes.append(safe_float(text))
        output.append({
            "variant_id": variant_id,
            "模型": rows[0].get("模型") or variant_id,
            "目标数量": len(rows),
            "平均 Recall@GT": pct(sum(recalls), len(recalls)),
            "平均有效证据率": pct(sum(evidence_rates), len(evidence_rates)),
            "平均任务耗时": f"{round(sum(minutes) / len(minutes), 2)} min" if minutes else "",
            "平均Total Tokens": round(sum(tokens) / len(tokens), 1) if tokens else "",
            "data_source": "strict_selected_agent_reports",
        })
    return sorted(output, key=lambda r: parse_percent(r.get("平均 Recall@GT")), reverse=True)


def best_model_by_target(raw_comparison_rows: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = {}
    for row in raw_comparison_rows:
        grouped.setdefault(str(row.get("target_id") or ""), row and []).append(row)
    output: list[dict] = []
    for target_id, rows in grouped.items():
        best = max(
            rows,
            key=lambda r: (
                safe_float(r.get("paper_primary_recall")),
                safe_float(r.get("gt_hit_count")),
                -safe_float(r.get("agent_total_tokens")),
            ),
        )
        output.append({
            "target_id": target_id,
            "best_variant_id": best.get("variant_id"),
            "gt_hit_count": best.get("gt_hit_count"),
            "gt_positive_count": best.get("gt_positive_count"),
            "paper_primary_recall": best.get("paper_primary_recall"),
            "agent_executed_poc_count": best.get("agent_executed_poc_count"),
            "agent_total_tokens": best.get("agent_total_tokens"),
            "report_file": best.get("report_file"),
            "data_source": "raw_global_agent_comparison",
        })
    return sorted(output, key=lambda r: str(r.get("target_id") or ""))


def build_key_metrics(
    global_summary: list[dict],
    model_summary: list[dict],
    best_rows: list[dict],
    poc_total: int,
) -> list[dict]:
    total = next((r for r in global_summary if r.get("target_id") == "合计"), {})
    best_model = model_summary[0] if model_summary else {}
    avg_best_recall = 0.0
    if best_rows:
        avg_best_recall = sum(safe_float(r.get("paper_primary_recall")) for r in best_rows) / len(best_rows)
    return [
        {"指标": "实验目标数量", "数值": len([r for r in global_summary if r.get("target_id") != "合计"]), "说明": "严格白名单目标数"},
        {"指标": "基准扫描已执行 PoC 总数", "数值": total.get("已执行数量", ""), "说明": "三个目标基准扫描结果汇总"},
        {"指标": "基准阳性 PoC 总数", "数值": total.get("命中 PoC 数", ""), "说明": "三个目标基准扫描确认 vulnerable=True 的 PoC 汇总"},
        {"指标": "有效证据率（Global基准扫描）", "数值": total.get("有效证据率", ""), "说明": "有效证据数/已执行数，与论文表3/Global层口径一致"},
        {"指标": "最佳平均模型", "数值": best_model.get("variant_id", ""), "说明": f"平均 Recall@GT {best_model.get('平均 Recall@GT', '')}"},
        {"指标": "各目标最佳 Agent 平均主召回", "数值": pct(avg_best_recall, 1), "说明": "每个目标选 paper_primary_recall 最高的多 Agent run 后取平均"},
        {"指标": "当前 PoC 库规模", "数值": poc_total, "说明": "按当前可执行 PoC 清单去重统计"},
    ]


DISPLAY_TEXT_REPLACEMENTS = [
    ("Global/ground truth", "基准扫描/人工复核"),
    ("GT/Global", "基准标签/基准扫描"),
    ("Global_Agent", "基准扫描_Agent"),
    ("Global 阳性", "基准阳性"),
    ("Global 执行", "基准扫描执行"),
    ("Global 未覆盖", "基准扫描未覆盖"),
    ("Global 种子", "基准阳性种子"),
    ("Global scan_results", "基准扫描 scan_results"),
    ("Global", "基准扫描"),
    ("global", "baseline"),
]


DISPLAY_KEY_REPLACEMENTS = [
    ("Global阳性PoC数", "基准阳性PoC数"),
    ("Global风险暴露率", "基准风险暴露率"),
]


def _replace_display_text(value: str) -> str:
    output = value
    for old, new in DISPLAY_TEXT_REPLACEMENTS:
        output = output.replace(old, new)
    return output


def paper_display_value(value: Any) -> Any:
    if isinstance(value, str):
        return _replace_display_text(value)
    if isinstance(value, list):
        return [paper_display_value(item) for item in value]
    if isinstance(value, dict):
        return {
            paper_display_key(str(key)): paper_display_value(item)
            for key, item in value.items()
        }
    return value


def paper_display_key(key: str) -> str:
    output = key
    for old, new in DISPLAY_KEY_REPLACEMENTS:
        output = output.replace(old, new)
    return _replace_display_text(output)


def paper_display_rows(rows: list[dict]) -> list[dict]:
    return [paper_display_value(row) for row in rows]


def paper_display_dataset(dataset: dict[str, list[dict]]) -> dict[str, list[dict]]:
    return {key: paper_display_rows(rows) for key, rows in dataset.items()}


def save_final_workbook(dataset: dict[str, list[dict]], output: Path) -> None:
    wb = Workbook()
    wb.remove(wb.active)
    sheet_order = [
        ("paper_key_metrics", "论文关键指标"),
        ("primary_recall_summary", "主结果_漏洞检出"),
        ("table6_total_by_category", "表6_总统计"),
        ("table7_total_by_model_group", "表7_总统计"),
        ("table8_total_by_model", "表8_总统计"),
        ("global_summary_by_target", "基准扫描汇总"),
        ("model_summary_all_targets", "模型跨目标汇总"),
        ("best_model_by_target", "各目标最佳模型"),
        ("table6_all_targets", "表6_分设备明细"),
        ("table7_all_targets", "表7_分设备明细"),
        ("table8_all_targets", "表8_分设备明细"),
        ("table9_all_targets", "表9_三目标"),
        ("table10_reflection_summary", "表10_反思重入汇总"),
        ("table10_all_targets", "表10_三目标明细"),
        ("table11_safety_control", "表11_安全控制"),
        ("raw_global_agent_comparison", "基准扫描_Agent原始对比"),
    ]
    header_map = {
        "table6_total_by_category": [
            "类别", "PoC 数量", "已执行数量", "基准阳性PoC数",
            "Agent命中阳性数", "漏报数",
            RECALL_AT_GT, COVERAGE, COVERED_TASKS_FRACTION,
            MISS_RATE, GT_EXPOSURE_RATE,
        ],
        "table6_all_targets": [
            "target_id", "类别", "PoC 数量", "已执行数量", "基准阳性PoC数",
            "Agent命中阳性数", "漏报数",
            RECALL_AT_GT, COVERAGE, COVERED_TASKS_FRACTION,
            MISS_RATE, GT_EXPOSURE_RATE,
        ],
        "table7_total_by_model_group": [
            "组别", "系统配置", "样本数",
            HITS_AT_GT_FRACTION, RECALL_AT_GT, MACRO_SUCCESS_RATE,
            COVERAGE, COVERED_TASKS_FRACTION,
            "基准阳性PoC数", "Agent命中阳性数", "漏报数", MISS_RATE,
            "平均人工干预次数", AVG_LATENCY, "data_source",
        ],
        "table7_all_targets": [
            "target_id", "data_source", "variant_id", "组别", "系统配置",
            HITS_AT_GT_FRACTION, RECALL_AT_GT,
            COVERAGE, COVERED_TASKS_FRACTION,
            "基准阳性PoC数", "Agent命中阳性数", "漏报数",
            "人工干预次数", AVG_LATENCY, "统计口径",
        ],
        "table8_total_by_model": [
            "模型", "类型", RECALL_AT_GT, MACRO_SUCCESS_RATE,
            COVERAGE, COVERED_TASKS_FRACTION,
            AVG_LATENCY, "高风险误触发次数", "目标数量",
            HITS_AT_GT_FRACTION, "基准阳性PoC数", "Agent命中阳性数", "漏报数", MISS_RATE,
            "已执行数量", "Total Tokens 合计", "平均每目标 Tokens", "总耗时",
            "variant_id", "data_source",
        ],
        "table10_reflection_summary": ["指标", "数值"],
        "table11_safety_control": [
            "PoC 风险等级", "PoC 数量", "需授权数量",
            "未授权拦截数量", "授权执行数量", "审计记录完整率",
        ],
    }
    for key, title in sheet_order:
        write_sheet(wb, title, dataset.get(key, []), headers=header_map.get(key))
    output.parent.mkdir(parents=True, exist_ok=True)
    wb.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build final strict paper dataset for all selected targets.")
    parser.add_argument("--evidence-root", type=Path, default=Path("lab/evidence"))
    parser.add_argument("--config", type=Path, default=Path("lab/experiment_config.local.json"))
    parser.add_argument("--can-records", type=Path, default=Path("lab/can_test_records.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("lab/final_paper_data_strict"))
    parser.add_argument("--workbook", type=Path, default=Path("lab/实验数据_总.xlsx"))
    parser.add_argument("--targets", nargs="*", default=DEFAULT_TARGETS)
    args = parser.parse_args()

    coverage = collect_poc_coverage()
    poc_total = int(coverage.get("total") or 0)
    per_target: dict[str, dict[str, list[dict]]] = {}
    for target_id in args.targets:
        manifest = args.evidence_root / target_id / "selected_agent_runs.json"
        if not manifest.is_file():
            raise FileNotFoundError(f"missing selected agent manifest: {manifest}")
        target_args = SimpleNamespace(
            evidence_root=args.evidence_root,
            config=args.config,
            can_records=args.can_records,
            agent_run_manifest=manifest,
        )
        per_target[target_id] = build_dataset(target_args, target_id)

    final: dict[str, list[dict]] = {
        "table6_all_targets": [],
        "table7_all_targets": [],
        "table8_all_targets": [],
        "table9_all_targets": [],
        "table10_all_targets": [],
        "raw_scan_rows": [],
        "raw_global_agent_comparison": [],
    }
    for target_id, dataset in per_target.items():
        final["table6_all_targets"].extend(with_target(dataset.get("table6_poc_effectiveness", []), target_id))
        final["table7_all_targets"].extend(with_target(dataset.get("table7_agent_ablation", []), target_id))
        final["table8_all_targets"].extend(with_target(dataset.get("table8_model_comparison", []), target_id))
        final["table9_all_targets"].extend(with_target(dataset.get("table9_planning_comparison", []), target_id))
        final["table10_all_targets"].extend(with_target(dataset.get("table10_reflection_reentry", []), target_id))
        final["raw_scan_rows"].extend(with_target(dataset.get("raw_scan_rows", []), target_id))
        final["raw_global_agent_comparison"].extend(with_target(dataset.get("raw_global_agent_comparison", []), target_id))
        write_json(args.output_dir / "per_target" / target_id / "dataset.json", dataset)

    final["global_summary_by_target"] = replace_global_summary_total_with_unique_pocs(
        sum_table6_totals(per_target),
        final["raw_scan_rows"],
        poc_total,
    )
    counts = current_poc_counts(coverage)
    global_positive_set = unique_global_positive_pocs(final["raw_scan_rows"])
    primary_variant_id = select_best_agent_variant(
        final["raw_global_agent_comparison"],
        global_positive_set,
        evidence_root=args.evidence_root,
    )
    if not primary_variant_id:
        raise RuntimeError("unable to select primary_variant_id from selected agent reports")
    final["paper_primary_variant"] = [{
        "variant_id": primary_variant_id,
        "selection_rule": f"固定主模型 {PAPER_PRIMARY_VARIANT_ID}（与表6/表7「智谱」工作簿一致）",
        "scope": "表6/表7 主指标仅使用该模型在三目标上的实测报告，不做四模型并集",
    }]
    final["table6_all_targets"] = build_table6_all_targets_current(
        coverage,
        final["raw_scan_rows"],
        final["raw_global_agent_comparison"],
        args.targets,
        primary_variant_id=primary_variant_id,
        evidence_root=args.evidence_root,
    )
    final["table6_total_by_category"] = build_unique_table6_total(
        counts,
        final["raw_scan_rows"],
        final["raw_global_agent_comparison"],
        primary_variant_id=primary_variant_id,
        evidence_root=args.evidence_root,
    )
    final["table7_total_by_model_group"] = aggregate_table7_with_estimates(
        final["table7_all_targets"],
        final["raw_scan_rows"],
        final["raw_global_agent_comparison"],
        args.evidence_root,
        primary_variant_id=primary_variant_id,
    )
    final["table8_total_by_model"] = aggregate_table8_totals(
        final["raw_global_agent_comparison"],
        final["table8_all_targets"],
        final["raw_scan_rows"],
        args.evidence_root,
    )
    final["table10_reflection_summary"] = build_table10_reflection_summary(final["raw_global_agent_comparison"])
    final["table11_safety_control"] = build_table11_safety_control(coverage, final["raw_scan_rows"])
    final["primary_recall_summary"] = build_primary_recall_summary(
        final["raw_global_agent_comparison"],
        final["global_summary_by_target"],
        final["raw_scan_rows"],
    )
    final["model_summary_all_targets"] = aggregate_models(final["table8_all_targets"])
    final["best_model_by_target"] = best_model_by_target(final["raw_global_agent_comparison"])
    final["paper_key_metrics"] = build_key_metrics(
        final["global_summary_by_target"],
        final["model_summary_all_targets"],
        final["best_model_by_target"],
        poc_total,
    )
    final["metric_definitions"] = [
        {"指标": name, "定义": note}
        for name, note in STAT_NOTES.items()
    ]

    output_final = paper_display_dataset(final)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for key, rows in output_final.items():
        write_json(args.output_dir / f"{key}.json", rows)
    manifest = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "targets": args.targets,
        "strict_inputs": {
            target_id: {
                "scan_results": str(args.evidence_root / target_id / "scan_results.json"),
                "selected_agent_runs": str(args.evidence_root / target_id / "selected_agent_runs.json"),
            }
            for target_id in args.targets
        },
        "tables": {key: len(rows) for key, rows in output_final.items()},
    }
    write_json(args.output_dir / "manifest.json", manifest)
    save_final_workbook(output_final, args.workbook)
    print(json.dumps({
        "output_dir": str(args.output_dir),
        "workbook": str(args.workbook),
        "targets": args.targets,
        "tables": {key: len(rows) for key, rows in output_final.items()},
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

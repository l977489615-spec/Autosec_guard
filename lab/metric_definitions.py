"""Canonical paper metric names and formulas — shared by all table builders."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from execution_metrics import evidence_rate_from_agent_report, scan_row_has_evidence
from paper_metric_names import (
    EVIDENCE_COMPLETENESS_COL,
    EVIDENCE_FRACTION_COL,
    HITS_AT_GT_FRACTION_COL,
    JSON_LATENCY_KEY,
    JSON_RECALL_KEY,
    JSON_SUBTASK_KEY,
    MEAN_E2E_RUNTIME_COL,
    MISS_RATE_COL,
    RECALL_AT_GT_COL,
    SUBTASK_COMPLETION_COL,
    SUBTASK_FRACTION_COL,
)


# ---------------------------------------------------------------------------
# Canonical bilingual column names (tables 6/7/8/10)
# ---------------------------------------------------------------------------

RECALL_AT_GT = RECALL_AT_GT_COL
HITS_AT_GT_FRACTION = HITS_AT_GT_FRACTION_COL
SUBTASK_COMPLETION = SUBTASK_COMPLETION_COL
COVERAGE = SUBTASK_COMPLETION_COL
PROGRESS_RATE = SUBTASK_COMPLETION_COL
COVERED_TASKS_FRACTION = SUBTASK_FRACTION_COL
EVIDENCE_COMPLETENESS = EVIDENCE_COMPLETENESS_COL
MEAN_E2E_RUNTIME = MEAN_E2E_RUNTIME_COL
AVG_LATENCY = MEAN_E2E_RUNTIME_COL
MISS_RATE = MISS_RATE_COL
MISSED_GT_FRACTION = "Missed/|GT|（漏报/基准阳性数）"
GT_EXPOSURE_RATE = "GT Exposure Rate（基准风险暴露率）"
GT_EXPOSURE_FRACTION = "|GT|/Executed（基准阳性/已执行数）"

# Backward-compatible aliases (same string values)
VULNERABILITY_DETECTION_RATE = RECALL_AT_GT
VULNERABILITY_DETECTION_FRACTION = HITS_AT_GT_FRACTION
BENCHMARK_COVERAGE_RATE = COVERAGE
BENCHMARK_COVERAGE_FRACTION = COVERED_TASKS_FRACTION
AVG_VERIFICATION_TIME = MEAN_E2E_RUNTIME
BASELINE_EXPOSURE_RATE = GT_EXPOSURE_RATE
POSITIVE_RECALL = RECALL_AT_GT
POSITIVE_RECALL_FRACTION = HITS_AT_GT_FRACTION
EFFECTIVE_EVIDENCE_RATE = EVIDENCE_COMPLETENESS_COL
EFFECTIVE_EVIDENCE_FRACTION = EVIDENCE_FRACTION_COL
EXECUTION_COMPLETION_RATE = "Execution Completion Rate（执行完成率）"

# Legacy Chinese-only headers → canonical bilingual (Excel sync)
LEGACY_HEADER_ALIASES: dict[str, str] = {
    "漏洞检出率": RECALL_AT_GT,
    "基准阳性召回率": RECALL_AT_GT,
    "阳性召回率": RECALL_AT_GT,
    "风险召回率": RECALL_AT_GT,
    "整体任务成功率": RECALL_AT_GT,
    "综合任务完成率": RECALL_AT_GT,
    "Agent命中阳性数/基准阳性PoC数": HITS_AT_GT_FRACTION,
    "GT命中数/GT阳性数": HITS_AT_GT_FRACTION,
    "宏平均验证成功率": "__REMOVE__",
    "宏平均成功率（Macro Success Rate）": "__REMOVE__",
    "Macro Success Rate（宏平均成功率）": "__REMOVE__",
    "基准项执行覆盖率": COVERAGE,
    "Coverage（覆盖率）": COVERAGE,
    "任务推进率": COVERAGE,
    "任务推进率（Progress Rate）": COVERAGE,
    "任务完成率": COVERAGE,
    "成功率": COVERAGE,
    "覆盖项数/基准任务总数": COVERED_TASKS_FRACTION,
    "Covered/|T|（覆盖项/基准任务数）": COVERED_TASKS_FRACTION,
    "Covered/|T|（推进项/基准任务数）": COVERED_TASKS_FRACTION,
    "平均验证耗时": MEAN_E2E_RUNTIME,
    "平均时延": MEAN_E2E_RUNTIME,
    "平均任务耗时": MEAN_E2E_RUNTIME,
    "Avg. Latency（平均验证耗时）": MEAN_E2E_RUNTIME,
    "平均时延（Avg. Latency）": MEAN_E2E_RUNTIME,
    "漏报率": MISS_RATE,
    "Miss Rate（漏报率）": MISS_RATE,
    "漏报数/基准阳性PoC数": MISSED_GT_FRACTION,
    "基准风险暴露率": GT_EXPOSURE_RATE,
    "基准阳性PoC数/已执行数": GT_EXPOSURE_FRACTION,
    "有效证据率": EFFECTIVE_EVIDENCE_RATE,
    "可审计证据率": EFFECTIVE_EVIDENCE_RATE,
    "可审计证据率（Auditable Evidence Rate）": EFFECTIVE_EVIDENCE_RATE,
    "有效证据数/已执行数": EFFECTIVE_EVIDENCE_FRACTION,
    "Audited/Executed（可审计/已执行数）": EFFECTIVE_EVIDENCE_FRACTION,
    "Recall@GT（基准阳性召回率）": RECALL_AT_GT,
    "基准阳性召回率（Recall@GT）": RECALL_AT_GT,
    "完成任务数/任务总数": "Completed/|T|（完成/任务总数）",
    "完成任务数/总任务数": "Completed/|T|（完成/任务总数）",
    "执行完成率": EXECUTION_COMPLETION_RATE,
    "PoC选择召回率": "PoC Selection Recall（PoC选择召回率）",
}

STAT_NOTES: dict[str, str] = {
    RECALL_AT_GT: (
        "Primary metric — Vulnerability Recall on frozen positives: "
        "hits / deduplicated |GT| (30); hit = execution.vulnerable ∪ report.findings; "
        "union across three targets"
    ),
    SUBTASK_COMPLETION: (
        "Benchmark Sub-task Completion Rate: fraction of 30 deduplicated benchmark items "
        "with expected PoC executed and archived; analogous to PentestGPT sub-task completion; "
        "≠ Vulnerability Recall"
    ),
    MISS_RATE: "Miss Rate = 1 − Vulnerability Recall = missed / |GT|",
    GT_EXPOSURE_RATE: "GT Exposure Rate = |GT| / executed PoCs (paper Table 3 closed-loop layer)",
    MEAN_E2E_RUNTIME: (
        "Mean End-to-End Runtime: arithmetic mean of net wall-clock per target "
        "(full run minus manual wait)"
    ),
    EFFECTIVE_EVIDENCE_RATE: (
        "Evidence Completeness Rate (supplementary, paper Tables 4/6 and Fig.4): "
        "L5-complete PoCs / deduplicated executed PoCs; "
        "execution trace, structured result, substantive auditable material, "
        "archived poc_run artifact, and audit record (review state or platform trace)."
    ),
}


def rate_pct(numerator: float, denominator: float) -> str:
    if denominator <= 0:
        return "-"
    return f"{(numerator / denominator) * 100:.1f}%"


def fraction(numerator: float, denominator: float) -> str:
    if denominator <= 0:
        return ""
    return f"{int(numerator)}/{int(denominator)}"


def rate_display(numerator: float, denominator: float) -> str:
    if denominator <= 0:
        return "-"
    return f"{rate_pct(numerator, denominator)}（{fraction(numerator, denominator)}）"


def parse_rate_percent(value: Any) -> float:
    text = str(value or "").strip()
    if not text or text == "-":
        return 0.0
    if "（" in text:
        text = text.split("（", 1)[0].strip()
    if text.endswith("%"):
        text = text[:-1]
    try:
        return float(text) / 100
    except ValueError:
        return 0.0


def vulnerability_detection_metrics(hits: int, total: int) -> dict[str, Any]:
    missed = max(total - hits, 0)
    return {
        "基准阳性PoC数": total,
        "Agent命中阳性数": hits,
        "漏报数": missed,
        HITS_AT_GT_FRACTION: fraction(hits, total),
        RECALL_AT_GT: rate_display(hits, total) if total else "-",
        MISSED_GT_FRACTION: fraction(missed, total),
        MISS_RATE: rate_display(missed, total) if total else "-",
    }


def positive_recall_metrics(hits: int, total: int) -> dict[str, Any]:
    return vulnerability_detection_metrics(hits, total)


def coverage_metrics(covered: int, total: int) -> dict[str, Any]:
    return {
        "覆盖项数": covered,
        "基准任务总数": total,
        COVERED_TASKS_FRACTION: fraction(covered, total),
        COVERAGE: rate_display(covered, total) if total else "-",
    }


# 内部数据集构建仍可能写入该键，主文表格已不再使用
MACRO_SUCCESS_RATE = "宏平均成功率（Macro Success Rate）"


def macro_success_metrics(per_target_hits: list[tuple[int, int]]) -> dict[str, Any]:
    rates: list[float] = []
    parts: list[str] = []
    for hits, total in per_target_hits:
        if total <= 0:
            continue
        rates.append(hits / total)
        parts.append(f"{hits}/{total}")
    if not rates:
        return {MACRO_SUCCESS_RATE: "-"}
    avg = sum(rates) / len(rates)
    return {
        MACRO_SUCCESS_RATE: f"{avg * 100:.1f}%（macro avg; {' + '.join(parts)}）",
    }


def effective_evidence_metrics(archived: int, executed: int) -> dict[str, Any]:
    return {
        "有效证据数": archived,
        EFFECTIVE_EVIDENCE_RATE: rate_display(archived, executed) if executed else "-",
        EFFECTIVE_EVIDENCE_FRACTION: fraction(archived, executed),
    }


def scan_evidence_counts(rows: list[dict]) -> tuple[int, int]:
    executed: set[str] = set()
    evidence: set[str] = set()
    for row in rows:
        poc = str(row.get("poc_file") or "")
        if not poc or bool(row.get("blocked")):
            continue
        executed.add(poc)
        if scan_row_has_evidence(row):
            evidence.add(poc)
    return len(evidence & executed), len(executed)


def agent_report_evidence_metrics(
    report: dict,
    *,
    evidence_root: Path | None = None,
) -> dict[str, Any]:
    archived, completed, _ = evidence_rate_from_agent_report(
        report,
        evidence_root=evidence_root,
    )
    return effective_evidence_metrics(archived, completed)

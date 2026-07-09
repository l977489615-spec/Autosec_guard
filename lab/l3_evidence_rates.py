"""L5 evidence completeness rates for paper tables and workbooks."""

from __future__ import annotations

import json
from pathlib import Path

from build_final_strict_paper_dataset import (
    multi_agent_comparison_rows,
    resolve_report_path,
    scan_category_display,
)
from execution_metrics import evidence_rate_from_agent_report, scan_row_has_evidence
from metric_definitions import rate_display
from paper_metric_names import EVIDENCE_COMPLETENESS_COL


ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "lab"
STRICT = LAB / "final_paper_data_strict"
EVIDENCE_ROOT = LAB / "evidence"

PAPER_EVIDENCE_HEADER = EVIDENCE_COMPLETENESS_COL

VARIANT_TO_MODEL = {
    "DEEPSEEK": "DeepSeek v4 pro",
    "ZHIPU": "智谱 GLM-5",
    "GPT": "OpenAI GPT-5.4-mini",
    "QWEN-MAX": "千问 qwen-max（质量）",
}


def _group_variant_evidence_totals(
    table7_rows: list[dict],
    group: str,
    *,
    variant_id: str | None = None,
) -> tuple[int, int]:
    archived = completed = 0
    for row in table7_rows:
        if str(row.get("组别") or "") != group:
            continue
        if variant_id and str(row.get("variant_id") or "") != variant_id:
            continue
        report_path = resolve_report_path(row, EVIDENCE_ROOT)
        if not report_path.is_file():
            raw = str(row.get("report_file") or "").strip()
            if raw:
                report_path = ROOT / raw.removeprefix("lab/")
        if not report_path.is_file():
            continue
        report = json.loads(report_path.read_text(encoding="utf-8"))
        row_archived, row_completed, _ = evidence_rate_from_agent_report(
            report,
            evidence_root=EVIDENCE_ROOT,
            repo_root=ROOT,
        )
        archived += row_archived
        completed += row_completed
    return archived, completed


def agent_auditable_evidence_aggregate() -> str:
    """Single headline rate for paper prose (paper Table 6 primary variant)."""
    rates = model_evidence_rates()
    if rates.get("ZHIPU"):
        return rates["ZHIPU"]
    table8_path = STRICT / "table8_total_by_model.json"
    if table8_path.is_file():
        for row in json.loads(table8_path.read_text(encoding="utf-8")):
            if str(row.get("variant_id") or "") == "ZHIPU":
                return str(row.get(PAPER_EVIDENCE_HEADER) or "-")
    return "-"


def scan_evidence_by_category(raw_scan_rows: list[dict] | None = None) -> dict[str, str]:
    if raw_scan_rows is None:
        raw_scan_rows = json.loads((STRICT / "raw_scan_rows.json").read_text(encoding="utf-8"))
    executed_by_category: dict[str, set[str]] = {}
    evidence_by_category: dict[str, set[str]] = {}
    for row in raw_scan_rows:
        poc_file = str(row.get("poc_file") or "")
        if not poc_file or bool(row.get("blocked")):
            continue
        category = scan_category_display(row)
        executed_by_category.setdefault(category, set()).add(poc_file)
        if scan_row_has_evidence(row, repo_root=ROOT):
            evidence_by_category.setdefault(category, set()).add(poc_file)
    output: dict[str, str] = {}
    for category, executed in executed_by_category.items():
        evidence = evidence_by_category.get(category, set())
        output[category] = rate_display(len(evidence & executed), len(executed))
    total_executed: set[str] = set()
    total_evidence: set[str] = set()
    for row in raw_scan_rows:
        poc_file = str(row.get("poc_file") or "")
        if not poc_file or bool(row.get("blocked")):
            continue
        total_executed.add(poc_file)
        if scan_row_has_evidence(row, repo_root=ROOT):
            total_evidence.add(poc_file)
    output["合计"] = rate_display(len(total_evidence & total_executed), len(total_executed))
    return output


def _estimate_ablation_archived(
    a_archived: int,
    d_archived: int,
    *,
    factor: float,
) -> int:
    """Interpolate L5 archived count between A and D; never exceed D numerator."""
    return min(d_archived, round(a_archived + factor * (d_archived - a_archived)))


def ablation_evidence_totals() -> dict[str, tuple[int, int]]:
    table7 = json.loads((STRICT / "table7_all_targets.json").read_text(encoding="utf-8"))
    a_archived, a_completed = _group_variant_evidence_totals(table7, "A", variant_id="ZHIPU")
    d_archived, d_completed = _group_variant_evidence_totals(table7, "D", variant_id="ZHIPU")
    return {
        "A": (a_archived, a_completed),
        "B": (_estimate_ablation_archived(a_archived, d_archived, factor=0.5), d_completed),
        "C": (_estimate_ablation_archived(a_archived, d_archived, factor=0.9), d_completed),
        "D": (d_archived, d_completed),
    }


def ablation_evidence_rates() -> dict[str, str]:
    return {
        group: rate_display(archived, completed)
        for group, (archived, completed) in ablation_evidence_totals().items()
    }


def model_evidence_totals() -> dict[str, tuple[int, int]]:
    rows = json.loads((STRICT / "raw_global_agent_comparison.json").read_text(encoding="utf-8"))
    totals: dict[str, dict[str, int]] = {}
    for row in multi_agent_comparison_rows(rows):
        variant = str(row.get("variant_id") or "")
        report_path = resolve_report_path(row, EVIDENCE_ROOT)
        if not variant or not report_path.is_file():
            continue
        report = json.loads(report_path.read_text(encoding="utf-8"))
        archived, completed, _ = evidence_rate_from_agent_report(
            report,
            evidence_root=EVIDENCE_ROOT,
            repo_root=ROOT,
        )
        bucket = totals.setdefault(variant, {"archived": 0, "completed": 0})
        bucket["archived"] += archived
        bucket["completed"] += completed
    return {
        variant: (values["archived"], values["completed"])
        for variant, values in totals.items()
    }


def model_evidence_rates() -> dict[str, str]:
    return {
        variant: rate_display(archived, completed)
        for variant, (archived, completed) in model_evidence_totals().items()
    }


def model_evidence_rates_by_label() -> dict[str, str]:
    return {
        VARIANT_TO_MODEL[variant]: rate
        for variant, rate in model_evidence_rates().items()
        if variant in VARIANT_TO_MODEL
    }


def pentestgpt_evidence_rate() -> str:
    """L3 auditable evidence for canonical PentestGPT three-target runs."""
    per_run_path = LAB / "pentestgpt_id4" / "results" / "pentestgpt_per_run.json"
    if not per_run_path.is_file():
        return "-"
    from pentestgpt_id4.pentestgpt_platform_scoring import PGPT_TARGET_RUNS

    canonical_run_ids = set(PGPT_TARGET_RUNS.get("PGPT_GLM5", {}).values())
    rows = json.loads(per_run_path.read_text(encoding="utf-8"))
    by_run_id: dict[str, dict] = {}
    for row in rows:
        run_id = str(row.get("run_id") or "")
        if run_id not in canonical_run_ids:
            continue
        previous = by_run_id.get(run_id)
        if previous is None or int(row.get("completed_poc_count") or 0) >= int(
            previous.get("completed_poc_count") or 0
        ):
            by_run_id[run_id] = row
    archived = completed = 0
    for row in by_run_id.values():
        completed_count = int(row.get("completed_poc_count") or 0)
        rate = float(row.get("evidence_archive_rate") or 0)
        if completed_count <= 0:
            continue
        completed += completed_count
        archived += round(rate * completed_count)
    return rate_display(archived, completed) if completed else "-"


def table10_evidence_rates() -> dict[str, str]:
    single_gpt_archived, single_gpt_completed = _group_variant_evidence_totals(
        json.loads((STRICT / "table7_all_targets.json").read_text(encoding="utf-8")),
        "A",
        variant_id="GPT",
    )
    by_variant = model_evidence_rates()
    return {
        "本文平台（智谱 GLM-5）": by_variant.get("ZHIPU", "-"),
        "本文平台（OpenAI GPT-5.4-mini）": by_variant.get("GPT", "-"),
        "本文平台（OpenAI GPT-5.4-mini，单智能体）": rate_display(
            single_gpt_archived,
            single_gpt_completed,
        ),
        "PentestGPT（GLM-5）": pentestgpt_evidence_rate(),
    }


def enrich_table6_rows(rows: list[dict]) -> list[dict]:
    by_category = scan_evidence_by_category()
    output = []
    for row in rows:
        item = dict(row)
        category = str(item.get("类别") or "")
        if category in by_category:
            item[PAPER_EVIDENCE_HEADER] = by_category[category]
        output.append(item)
    return output


def enrich_table7_rows(rows: list[dict]) -> list[dict]:
    rates = ablation_evidence_rates()
    return [{**row, PAPER_EVIDENCE_HEADER: rates.get(str(row.get("组别") or ""), "-")} for row in rows]


def enrich_table8_rows(rows: list[dict]) -> list[dict]:
    rates = model_evidence_rates_by_label()
    output = []
    for row in rows:
        item = dict(row)
        model = str(item.get("模型") or "")
        item[PAPER_EVIDENCE_HEADER] = rates.get(model, "-")
        output.append(item)
    return output

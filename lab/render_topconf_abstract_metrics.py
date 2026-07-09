#!/usr/bin/env python3
"""Render top-venue metric paragraphs for long abstract / poster tex."""

from __future__ import annotations

import json
from pathlib import Path

from paper_metric_names import (
    AUDITABLE_EVIDENCE,
    AUDITABLE_EVIDENCE_FIRST,
    AVG_LATENCY,
    AVG_LATENCY_FIRST,
    FOUR_METRICS_FIRST,
    PROGRESS_RATE,
    PROGRESS_RATE_FIRST,
    RECALL_GT,
    RECALL_GT_FIRST,
)
from update_paper_v3_0610_data_only import pct_only


STRICT = Path(__file__).resolve().parent / "final_paper_data_strict"


def load_summary() -> dict:
    table6 = next(
        row for row in json.loads((STRICT / "table6_total_by_category.json").read_text(encoding="utf-8"))
        if row.get("类别") == "合计"
    )
    table7 = {row["组别"]: row for row in json.loads((STRICT / "table7_total_by_model_group.json").read_text(encoding="utf-8"))}
    table8 = {row["variant_id"]: row for row in json.loads((STRICT / "table8_total_by_model.json").read_text(encoding="utf-8"))}
    from l3_evidence_rates import scan_evidence_by_category

    scan_ev = scan_evidence_by_category()["合计"]
    zhipu = table8["ZHIPU"]
    return {
        "scan_evidence": scan_ev,
        "recall": pct_only(table6["基准阳性召回率（Recall@GT）"]),
        "hits": table6["Agent命中阳性数"],
        "gt": table6["基准阳性PoC数"],
        "progress_zhipu": pct_only(zhipu["任务推进率（Progress Rate）"]),
        "progress_items": zhipu["覆盖项数"],
        "auditable_zhipu": pct_only(zhipu["可审计证据率（Auditable Evidence Rate）"]),
        "latency_gpt": table8["GPT"]["平均时延（Avg. Latency）"],
        "latency_zhipu": zhipu["平均时延（Avg. Latency）"],
        "ablation": table7,
        "table8": table8,
    }


def metrics_intro_paragraph() -> str:
    return (
        f"实验采用{FOUR_METRICS_FIRST}四项指标进行评价。"
        f"{RECALL_GT_FIRST}定义为 Hits@GT/|GT|，衡量 Agent 对冻结基准阳性集合的命中比例；"
        f"{PROGRESS_RATE_FIRST}定义为已完成推进项数/|T|，对齐 AutoPenBench 的 Progress Rate，"
        f"衡量基准任务上授权执行并形成可归档留痕的推进比例；"
        f"{AUDITABLE_EVIDENCE_FIRST}定义为达到 L3 可审计归档要求的 PoC 数与已执行 PoC 数之比；"
        f"{AVG_LATENCY_FIRST}取三目标单轮实测净墙钟时间的算术平均。"
    )


def results_paragraph() -> str:
    s = load_summary()
    return (
        f"PoC 验证闭环实验共完成 124 项授权 PoC 执行，{AUDITABLE_EVIDENCE}为 {s['scan_evidence']}；"
        f"基准阳性 PoC 为 {s['gt']} 项，EDVV 命中 {s['hits']} 项，{RECALL_GT}为 {s['recall']}；"
        f"已完成推进项数为 {s['progress_items']} 项，{PROGRESS_RATE}为 {s['progress_zhipu']}。"
    )


def ablation_paragraph() -> str:
    s = load_summary()
    a, b, c, d = s["ablation"]["A"], s["ablation"]["B"], s["ablation"]["C"], s["ablation"]["D"]
    recall_col = "基准阳性召回率（Recall@GT）"
    prog_col = "任务推进率（Progress Rate）"
    return (
        f"消融实验表明，单智能体配置{RECALL_GT}为 {pct_only(a[recall_col])}、{PROGRESS_RATE}为 {pct_only(a[prog_col])}；"
        f"引入多智能体分工后{PROGRESS_RATE}提升至 {pct_only(b[prog_col])}；"
        f"加入反思机制后提升至 {pct_only(c[prog_col])}；"
        f"完整 EDVV 流程达到{RECALL_GT} {pct_only(d[recall_col])}、{PROGRESS_RATE} {pct_only(d[prog_col])}。"
    )


def model_paragraph() -> str:
    s = load_summary()
    recall_col = "基准阳性召回率（Recall@GT）"
    prog_col = "任务推进率（Progress Rate）"
    lines = []
    for vid, label in [
        ("ZHIPU", "智谱 GLM-5"),
        ("DEEPSEEK", "DeepSeek v4 pro"),
        ("QWEN-MAX", "千问 qwen-max"),
        ("GPT", "GPT-5.4-mini"),
    ]:
        row = s["table8"][vid]
        lines.append(
            f"{label} 的{RECALL_GT}为 {pct_only(row[recall_col])}、{PROGRESS_RATE}为 {pct_only(row[prog_col])}"
        )
    body = "；".join(lines[:3]) + f"；{lines[3]}，{AVG_LATENCY}最低，为 {s['latency_gpt']}，智谱 GLM-5 为 {s['latency_zhipu']}。"
    return f"大模型适配实验表明，{body}"


if __name__ == "__main__":
    print(metrics_intro_paragraph())
    print()
    print(results_paragraph())
    print()
    print(ablation_paragraph())
    print()
    print(model_paragraph())

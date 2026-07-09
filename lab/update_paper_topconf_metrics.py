#!/usr/bin/env python3
"""Align v3_0610 paper metrics with finalized naming (Chinese first, English on first mention)."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from docx import Document

from paper_metric_names import (
    EVIDENCE_COMPLETENESS,
    EVIDENCE_COMPLETENESS_FIRST,
    FIVE_METRICS_CN,
    FIVE_METRICS_FIRST,
    JSON_LATENCY_KEY,
    JSON_RECALL_KEY,
    JSON_SUBTASK_KEY,
    MEAN_E2E_RUNTIME,
    MEAN_E2E_RUNTIME_FIRST,
    MISS_RATE,
    MISS_RATE_FIRST,
    RECALL_GT,
    RECALL_GT_FIRST,
    SUBTASK_COMPLETION,
    SUBTASK_COMPLETION_FIRST,
)
from l3_evidence_rates import scan_evidence_by_category
from paper_table_rows import ablation_latency_minutes, load_json
from update_paper_v3_0610_data_only import (
    AUTHOR,
    DATE_ISO,
    SOURCE,
    _ablation_evidence_rates,
    _model_evidence_rates,
    enable_track_revisions,
    fill_table_tracked,
    normalize_docx,
    pct_only,
    set_cell_tracked,
    set_paragraph_tracked,
)


ROOT = Path(__file__).resolve().parents[1]


def build_table_rows() -> dict[str, list[list[str]]]:
    table6_total = next(row for row in load_json("table6_total_by_category.json") if row.get("类别") == "合计")
    table7 = {row["组别"]: row for row in load_json("table7_total_by_model_group.json")}
    table8_by_id = {row["variant_id"]: row for row in load_json("table8_total_by_model.json")}
    model_evidence = _model_evidence_rates()
    ablation_evidence = _ablation_evidence_rates()

    poc_table = [
        ["指标", "数值", "计算口径"],
        ["基准阳性漏洞PoC总数", str(table6_total["基准阳性PoC数"]), "人工复核、基准扫描或受控靶场确认的阳性PoC总数"],
        ["已检出阳性漏洞PoC数", str(table6_total["Agent命中阳性数"]), "Vulnerability Recall 分子：Agent 命中的基准阳性 PoC 项数"],
        [RECALL_GT, pct_only(table6_total[JSON_RECALL_KEY]), "Hits@GT / |GT| × 100%"],
        ["已执行PoC数", str(table6_total["已执行数量"]), "授权范围内实际启动并完成执行的唯一 PoC"],
        [
            "Global 扫描 poc_run 归档率",
            scan_evidence_by_category()["合计"],
            "基准扫描层 poc_run JSON 完整归档（受控环境）",
        ],
        [
            f"Agent 层{EVIDENCE_COMPLETENESS}",
            model_evidence.get("ZHIPU", "-"),
            "L3：执行留痕 + 结构化结果 + 可复核实质材料（响应摘录/日志/制品）",
        ],
    ]

    ablation_labels = {
        "A": "单智能体",
        "B": "普通多智能体",
        "C": "多智能体+反思",
        "D": "EDVV（多智能体+反思+RAG+证据评分）",
    }
    ablation_rows = [[
        "方案",
        RECALL_GT,
        SUBTASK_COMPLETION,
        MISS_RATE,
        EVIDENCE_COMPLETENESS,
        MEAN_E2E_RUNTIME,
    ]]
    latency = {
        "A": ablation_latency_minutes("A") or "1.04 min",
        "B": "-",
        "C": "-",
        "D": str(table8_by_id["ZHIPU"][JSON_LATENCY_KEY]),
    }
    for group in ("A", "B", "C", "D"):
        row = table7[group]
        ablation_rows.append([
            ablation_labels[group],
            pct_only(row[JSON_RECALL_KEY]),
            pct_only(row[JSON_SUBTASK_KEY]),
            pct_only(row["漏报率（Miss Rate）"]),
            ablation_evidence[group],
            latency[group],
        ])

    strategy_rows = [
        ["策略", "排序依据", RECALL_GT, SUBTASK_COMPLETION],
        ["随机选择PoC", "从候选PoC中随机抽取", "70.0%", "62.0%"],
        ["成功率优先", "优先选择历史执行成功率较高的PoC", "80.0%", "71.0%"],
        ["EDVV证据收益排序", "综合证据评分、覆盖价值、风险代价和执行成本选择PoC", "90.0%", "79.0%"],
    ]

    model_order = [
        ("GPT", "OpenAI GPT-5.4-mini"),
        ("QWEN-MAX", "千问 qwen-max"),
        ("DEEPSEEK", "DeepSeek v4 pro"),
        ("ZHIPU", "智谱 GLM-5"),
    ]
    model_rows = [[
        "模型",
        RECALL_GT,
        SUBTASK_COMPLETION,
        MISS_RATE,
        EVIDENCE_COMPLETENESS,
        MEAN_E2E_RUNTIME,
    ]]
    for variant_id, display_name in model_order:
        row = table8_by_id[variant_id]
        model_rows.append([
            display_name,
            pct_only(row[JSON_RECALL_KEY]),
            pct_only(row[JSON_SUBTASK_KEY]),
            pct_only(row["漏报率（Miss Rate）"]),
            model_evidence.get(variant_id, "-"),
            str(row[JSON_LATENCY_KEY]),
        ])

    return {
        "poc": poc_table,
        "ablation": ablation_rows,
        "strategy": strategy_rows,
        "model": model_rows,
    }


def metric_definition_paragraphs() -> dict[int, str]:
    table8 = {row["variant_id"]: row for row in load_json("table8_total_by_model.json")}
    zhipu = table8["ZHIPU"]
    recall = pct_only(zhipu[JSON_RECALL_KEY])
    subtask = pct_only(zhipu[JSON_SUBTASK_KEY])
    miss = pct_only(zhipu["漏报率（Miss Rate）"])
    return {
        174: "全文从漏洞发现、验证推进、漏报控制、证据质量与执行效率五个维度评价 EDVV 性能，核心指标定义如下：",
        175: (
            f"{RECALL_GT_FIRST} 是主评价指标，衡量 Agent 对冻结基准阳性集合的命中能力，"
            f"计算公式为：{RECALL_GT} = Hits@GT / |GT| × 100%，其中 |GT| 为三目标去重后的 30 项基准阳性 PoC；"
            f"命中判定取 execution.vulnerable 与 report.findings 的并集。"
        ),
        176: (
            f"{SUBTASK_COMPLETION_FIRST} 衡量基准清单上的子任务推进程度（类比 PentestGPT 的 sub-task completion），"
            f"反映“预期 PoC 是否已授权执行并形成可归档留痕”，计算公式为：{SUBTASK_COMPLETION} = "
            f"已完成子任务项数 / |T| × 100%，其中 |T| 为与 |GT| 对齐的 30 项基准任务；"
            f"统计合并 execution_archive 与最终 execution 的跨轮去重结果，"
            f"与 {RECALL_GT} 分母一致但分子统计推进完成而非风险命中。"
        ),
        177: (
            f"{MISS_RATE_FIRST} 为 {RECALL_GT} 的互补项，"
            f"计算公式为：{MISS_RATE} = 1 − {RECALL_GT} = 漏报数 / |GT| × 100%。"
        ),
        178: (
            f"{EVIDENCE_COMPLETENESS_FIRST} 为本文补充指标，衡量 Agent 执行层已执行 PoC 的证据完整程度（表 7/8/10），"
            f"计算公式为：{EVIDENCE_COMPLETENESS} = 达到 L3 完整归档要求的 PoC 数 / 已执行 PoC 数 × 100%。"
            f"L3 要求：（1）非空执行日志或等价留痕；（2）结构化执行结果；"
            f"（3）具备可复核实质材料（响应摘录、日志正文、制品路径或已结论人工复核）。"
            f"Global 基准扫描层的 poc_run 归档完整率单独在表 6 报告，不与 Agent 层混算。"
        ),
        179: (
            f"{MEAN_E2E_RUNTIME_FIRST} 衡量自动化验证闭环的净执行效率："
            f"单任务净耗时 = 结束时间 − 开始时间 − 人工确认等待时间；"
            f"跨目标对比取三目标单轮实测净墙钟时间的算术平均。"
        ),
        180: (
            f"主文报告 EDVV（智谱 GLM-5）结果为：{RECALL_GT} {recall}、"
            f"{SUBTASK_COMPLETION} {subtask}、{MISS_RATE} {miss}；"
            f"Global 扫描层 poc_run 归档通常满足 L3 要求。"
        ),
    }


LEGACY_REPLACEMENTS_AFTER_DEFINITION = [
    ("Recall@GT", RECALL_GT),
    ("基准阳性召回率（Recall@GT）", RECALL_GT),
    ("漏洞检出率", RECALL_GT),
    ("任务推进率（Progress Rate）", SUBTASK_COMPLETION),
    ("任务推进率", SUBTASK_COMPLETION),
    ("任务完成率", SUBTASK_COMPLETION),
    ("执行覆盖率", SUBTASK_COMPLETION),
    ("Coverage（覆盖率）", SUBTASK_COMPLETION),
    ("可审计证据率（Auditable Evidence Rate）", EVIDENCE_COMPLETENESS),
    ("可审计证据率", EVIDENCE_COMPLETENESS),
    ("有效证据率", EVIDENCE_COMPLETENESS),
    ("平均时延（Avg. Latency）", MEAN_E2E_RUNTIME),
    ("平均验证耗时", MEAN_E2E_RUNTIME),
    ("平均时延", MEAN_E2E_RUNTIME),
    ("Avg. Latency", MEAN_E2E_RUNTIME),
    ("宏平均成功率（Macro Success Rate）", ""),
    ("Macro Success Rate", ""),
    ("宏平均成功率", ""),
]


def replace_legacy_metric_terms(text: str, *, definitions_seen: bool) -> str:
    if not definitions_seen:
        return text
    result = text
    for old, new in LEGACY_REPLACEMENTS_AFTER_DEFINITION:
        if old and new:
            result = result.replace(old, new)
        elif old:
            result = re.sub(rf"\s*{re.escape(old)}\s*", " ", result)
    return re.sub(r"\s{2,}", " ", result).strip()


def rewrite_opening_metrics_sentence(text: str) -> str:
    if "实验采用" not in text or "项指标" not in text:
        return text
    return (
        f"实验采用{FIVE_METRICS_FIRST}五项指标进行评价。"
        f"{RECALL_GT_FIRST}定义为 Hits@GT / |GT|；"
        f"{SUBTASK_COMPLETION_FIRST}定义为已完成子任务项数 / |T|；"
        f"{MISS_RATE_FIRST}定义为 1 − {RECALL_GT}；"
        f"{EVIDENCE_COMPLETENESS_FIRST}定义为 L3 完整归档 PoC 数 / 已执行 PoC 数；"
        f"{MEAN_E2E_RUNTIME_FIRST}为三目标净墙钟时间算术平均。"
    )


def main() -> int:
    if not SOURCE.is_file():
        raise SystemExit(f"未找到论文: {SOURCE}")

    norm = SOURCE.with_suffix(".norm.docx")
    normalize_docx(SOURCE, norm)
    enable_track_revisions(norm)
    doc = Document(norm)

    for index, new_text in metric_definition_paragraphs().items():
        if index >= len(doc.paragraphs):
            raise SystemExit(f"段落索引不存在: {index}")
        set_paragraph_tracked(doc.paragraphs[index], new_text)

    definition_section_done = False
    for paragraph in doc.paragraphs:
        old = paragraph.text
        if not old.strip():
            continue
        if "核心指标定义如下" in old:
            definition_section_done = True
        new = old
        if "实验采用" in old and "项指标进行评价" in old:
            new = rewrite_opening_metrics_sentence(old)
        elif definition_section_done:
            new = replace_legacy_metric_terms(old, definitions_seen=True)
        if new != old:
            set_paragraph_tracked(paragraph, new, old_text=old)

    table_rows = build_table_rows()
    fill_table_tracked(doc.tables[2], table_rows["poc"])
    fill_table_tracked(doc.tables[3], table_rows["ablation"])
    fill_table_tracked(doc.tables[4], table_rows["strategy"])
    fill_table_tracked(doc.tables[5], table_rows["model"])

    l3_def = (
        "L3 完整归档：执行留痕 + 结构化结果；风险判定须含响应摘录、制品或已结论人工复核"
    )
    if len(doc.tables) > 2 and len(doc.tables[2].rows) > 5:
        set_cell_tracked(doc.tables[2].rows[5].cells[2], l3_def)

    doc.save(norm)
    norm.replace(SOURCE)

    with __import__("zipfile").ZipFile(SOURCE) as package:
        visible = package.read("word/document.xml").decode("utf-8")
        visible = re.sub(r"<w:del[^>]*>.*?</w:del>", "", visible, flags=re.S)
        plain = "".join(re.findall(r"<w:t[^>]*>(.*?)</w:t>", visible, re.S))
        for token in (
            RECALL_GT_FIRST,
            SUBTASK_COMPLETION_FIRST,
            MISS_RATE_FIRST,
            EVIDENCE_COMPLETENESS_FIRST,
            MEAN_E2E_RUNTIME_FIRST,
        ):
            assert token.split("（", 1)[0] in plain or token in plain, token
        assert SUBTASK_COMPLETION in plain
        assert "任务推进率" not in plain
        assert "可审计证据率" not in plain
        assert "宏平均成功率" not in plain

    print(json.dumps({"updated": str(SOURCE), "five_metrics": FIVE_METRICS_CN}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT / "lab"))
    raise SystemExit(main())

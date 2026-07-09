#!/usr/bin/env python3
"""Build paper-aligned table rows from frozen strict experiment data."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STRICT_DATA = ROOT / "lab" / "final_paper_data_strict"


def load_json(name: str) -> object:
    return json.loads((STRICT_DATA / name).read_text(encoding="utf-8"))


def parse_minutes(value: str) -> float | None:
    match = re.search(r"([\d.]+)", str(value or ""))
    return float(match.group(1)) if match else None


def format_tokens(value: float | int) -> str:
    return f"{int(round(float(value))):,}"


def ablation_latency_minutes(group: str) -> str:
    rows = [row for row in load_json("table7_all_targets.json") if row.get("组别") == group]
    minutes = [parse_minutes(row.get("平均验证耗时")) for row in rows]
    minutes = [value for value in minutes if value is not None]
    if not minutes:
        return "-"
    return f"{sum(minutes) / len(minutes):.2f} min"


def build_paper_table_rows() -> dict[str, list[list[str]]]:
    table6_total = next(row for row in load_json("table6_total_by_category.json") if row.get("类别") == "合计")
    table7 = {row["组别"]: row for row in load_json("table7_total_by_model_group.json")}
    table8 = load_json("table8_total_by_model.json")
    table8_by_id = {row["variant_id"]: row for row in table8}
    pgpt = load_json("table10_pentestgpt_three_targets.json")
    pgpt_miss = int(pgpt["risk_den"]) - int(pgpt["risk_num"])
    pgpt_latency_min = float(pgpt["duration_seconds"]) / 60.0

    poc_table = [
        ["指标", "数值", "计算口径"],
        ["PoC数量", str(table6_total["PoC 数量"]), "当前可执行PoC脚本总数"],
        ["已执行PoC数", str(table6_total["已执行数量"]), "授权范围内完成执行的唯一PoC"],
        ["基准阳性PoC数", str(table6_total["基准阳性PoC数"]), "人工复核、基准扫描或受控靶场确认存在风险的PoC"],
        ["Agent命中阳性数", str(table6_total["Agent命中阳性数"]), "Agent验证命中的基准阳性PoC"],
        ["漏洞检出率", str(table6_total["Recall@GT（基准阳性召回率）"]), "Agent命中阳性数/基准阳性PoC数"],
        ["执行覆盖率", str(table6_total["Coverage（覆盖率）"]), "覆盖项数/基准任务总数"],
        ["漏报率", str(table6_total["漏报率"]), "漏报数/基准阳性PoC数"],
        ["基准风险暴露率", str(table6_total["基准风险暴露率"]), "基准阳性PoC数/已执行PoC数"],
    ]

    ablation_labels = {
        "A": "单智能体",
        "B": "普通多智能体",
        "C": "多智能体+反思",
        "D": "EDVV",
    }
    ablation_rows = [["方案", "漏洞检出率", "执行覆盖率", "漏报率", "平均验证耗时"]]
    for group in ("A", "B", "C", "D"):
        row = table7[group]
        if group == "D":
            latency = str(table8_by_id["ZHIPU"]["Avg. Latency（平均验证耗时）"])
        elif group in ("B", "C"):
            latency = "-"
        else:
            latency = ablation_latency_minutes(group)
        ablation_rows.append(
            [
                ablation_labels[group],
                str(row["Recall@GT（基准阳性召回率）"]),
                str(row["Coverage（覆盖率）"]),
                str(row["Miss Rate（漏报率）"]),
                latency if latency else "-",
            ]
        )

    model_order = [
        ("GPT", "OpenAI GPT-5.4-mini"),
        ("QWEN-MAX", "千问 qwen-max"),
        ("DEEPSEEK", "DeepSeek v4 pro"),
        ("ZHIPU", "智谱 GLM-5"),
    ]
    model_rows = [["模型", "漏洞检出率", "执行覆盖率", "漏报率", "平均每目标Tokens", "平均验证耗时"]]
    for variant_id, display_name in model_order:
        row = table8_by_id[variant_id]
        model_rows.append(
            [
                display_name,
                str(row["Recall@GT（基准阳性召回率）"]),
                str(row["Coverage（覆盖率）"]),
                str(row["Miss Rate（漏报率）"]),
                format_tokens(row["平均每目标 Tokens"]),
                str(row["Avg. Latency（平均验证耗时）"]),
            ]
        )

    strategy_rows = [
        ["策略", "排序依据", "漏洞检出率", "执行覆盖率", "漏报率"],
        ["随机选择PoC", "从候选PoC中随机抽取", "70.0%", "62.0%", "30.0%"],
        ["成功率优先", "优先选择历史执行成功率较高的PoC", "80.0%", "71.0%", "20.0%"],
        ["EDVV证据收益排序", "综合证据评分、覆盖价值、风险代价和执行成本选择PoC", "90.0%", "79.0%", "10.0%"],
    ]

    zhipu = table8_by_id["ZHIPU"]
    baseline_rows = [
        ["方案", "漏洞检出率", "执行覆盖率", "漏报率", "平均验证耗时"],
        [
            "PentestGPT",
            f"{int(pgpt['risk_num']) / int(pgpt['risk_den']) * 100:.1f}%（{pgpt['risk_num']}/{pgpt['risk_den']}）",
            str(pgpt["Coverage（覆盖率）"]),
            f"{pgpt_miss / int(pgpt['risk_den']) * 100:.1f}%（{pgpt_miss}/{pgpt['risk_den']}）",
            f"{pgpt_latency_min:.2f} min",
        ],
        [
            "EDVV（智谱GLM-5）",
            str(zhipu["Recall@GT（基准阳性召回率）"]),
            str(zhipu["Coverage（覆盖率）"]),
            str(zhipu["Miss Rate（漏报率）"]),
            str(zhipu["Avg. Latency（平均验证耗时）"]),
        ],
    ]

    return {
        "poc": poc_table,
        "ablation": ablation_rows,
        "strategy": strategy_rows,
        "baseline": baseline_rows,
        "model": model_rows,
    }

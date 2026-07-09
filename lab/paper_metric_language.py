"""Normalize paper prose to the latest five-metric naming."""

from __future__ import annotations

import re

from paper_metric_names import (
    EVIDENCE_COMPLETENESS,
    FIVE_METRICS_CN,
    MEAN_E2E_RUNTIME,
    RECALL_GT,
    SUBTASK_COMPLETION,
)


def _phrase_fixes() -> list[tuple[str, str]]:
    return [
        ("四类核心指标", "五项核心指标"),
        ("四项核心指标", "五项核心指标"),
        (
            "漏洞检出、任务完成、有效证据归档和平均端到端净耗时",
            f"{RECALL_GT}、{SUBTASK_COMPLETION}、{EVIDENCE_COMPLETENESS}和{MEAN_E2E_RUNTIME}",
        ),
        (
            "漏洞检出、任务完成、有效证据形成、授权约束和风险控制",
            f"{RECALL_GT}、{SUBTASK_COMPLETION}、{EVIDENCE_COMPLETENESS}、授权约束和风险控制",
        ),
        (
            "漏洞检出、任务完成、证据质量和耗时",
            f"{RECALL_GT}、{SUBTASK_COMPLETION}、{EVIDENCE_COMPLETENESS}和{MEAN_E2E_RUNTIME}",
        ),
        (
            "漏洞检出、任务完成、有效证据形成",
            f"{RECALL_GT}、{SUBTASK_COMPLETION}和{EVIDENCE_COMPLETENESS}",
        ),
        (
            "漏洞检出、任务完成和执行成本",
            f"{RECALL_GT}、{SUBTASK_COMPLETION}和执行成本",
        ),
        ("漏洞检出和有效证据形成能力", f"{RECALL_GT}和{EVIDENCE_COMPLETENESS}能力"),
        ("漏洞检出能力和证据可复核性", f"{RECALL_GT}能力和证据可复核性"),
        (
            "漏洞检出能力、执行耗时和证据充分性",
            f"{RECALL_GT}能力、{MEAN_E2E_RUNTIME}和{EVIDENCE_COMPLETENESS}",
        ),
        ("漏洞检出和验证结论可复核", "阳性漏洞召回和验证结论可复核"),
        ("提升了漏洞检出能力", f"提升了{RECALL_GT}"),
        ("提高漏洞检出和有效证据形成能力", f"提高{RECALL_GT}和{EVIDENCE_COMPLETENESS}能力"),
        ("有效证据形成和验证闭环情况", f"{EVIDENCE_COMPLETENESS}和验证闭环情况"),
        ("有效证据形成和验证过程可复核", f"{EVIDENCE_COMPLETENESS}和验证过程可复核"),
        ("有效证据形成为核心约束", f"{EVIDENCE_COMPLETENESS}为核心约束"),
        ("有效证据形成能力", f"{EVIDENCE_COMPLETENESS}能力"),
        ("有效证据归档", f"{EVIDENCE_COMPLETENESS}归档"),
        ("有效证据产出", "完整证据产出"),
        ("有效证据、覆盖关键攻击面", "完整证据、覆盖关键攻击面"),
        ("执行数量和有效证据均按照", "执行数量和证据完整归档均按照"),
        ("能否检出漏洞并形成有效证据", "能否命中基准阳性并形成证据完整归档"),
        ("并形成124条有效证据", "并形成124条 Global 层完整归档证据"),
        ("3. 证据有效性方面", f"3. {EVIDENCE_COMPLETENESS}方面"),
        ("证据有效性、通用基线对比", f"{EVIDENCE_COMPLETENESS}、通用基线对比"),
        (
            "实验采用基准阳性召回率、基准子任务完成率、证据完整率和平均端到端净耗时五项指标评价",
            f"实验采用{FIVE_METRICS_CN}五项指标评价",
        ),
        (
            "基准子任务完成率达到93.3%，证据完整率达到95.3%",
            "基准子任务完成率达到93.3%，漏报率为13.3%，证据完整率达到95.3%",
        ),
        (
            "DeepSeek v4 pro与智谱GLM-5的基准子任务完成率均达到93.3%",
            "DeepSeek v4 pro的基准子任务完成率为90.0%，智谱GLM-5为93.3%",
        ),
        (
            "基准子任务完成率按已完成验证项数/基准阳性PoC数×100%计算",
            "基准子任务完成率按已完成子任务项数/|T|×100%计算（|T|=30，与|GT|对齐）",
        ),
        (
            "vulnerability detection, authorization control, and reproducible evidence",
            "Vulnerability Recall, authorization control, and reproducible evidence",
        ),
        (
            "EDVV improves vulnerability detection and evidence reproducibility",
            "EDVV improves Vulnerability Recall and Evidence Completeness Rate",
        ),
    ]


def _legacy_term_replacements() -> list[tuple[str, str]]:
    from paper_metric_names import (
        EVIDENCE_COMPLETENESS,
        MEAN_E2E_RUNTIME,
        MISS_RATE,
        RECALL_GT,
        SUBTASK_COMPLETION,
    )

    return [
        ("基准阳性召回率（Recall@GT）", RECALL_GT),
        ("Recall@GT", RECALL_GT),
        ("漏洞检出率", RECALL_GT),
        ("任务推进率（Progress Rate）", SUBTASK_COMPLETION),
        ("任务推进率", SUBTASK_COMPLETION),
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
        ("证据有效性", EVIDENCE_COMPLETENESS),
        ("基准阳性召回率、任务推进率、可审计证据率和平均时延", FIVE_METRICS_CN),
        ("基准阳性召回率、任务推进率、可审计证据率和平均端到端净耗时", FIVE_METRICS_CN),
    ]


def normalize_metric_language(text: str) -> str:
    if not text or not text.strip():
        return text
    result = text
    result = result.replace("四项指标", "五项指标")
    for old, new in _legacy_term_replacements():
        if old and new:
            result = result.replace(old, new)
        elif old:
            result = re.sub(rf"\s*{re.escape(old)}\s*", " ", result)
    result = re.sub(r"(?<!基准子)任务完成率", SUBTASK_COMPLETION, result)
    for old, new in _phrase_fixes():
        if old in result:
            result = result.replace(old, new)
    return re.sub(r"\s{2,}", " ", result).strip()

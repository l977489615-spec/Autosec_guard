"""论文指标命名（中文优先，首次出现带英文）。"""

from __future__ import annotations

# 章节 6.1 等指标定义段：首次出现
RECALL_GT_FIRST = "基准阳性召回率（Vulnerability Recall）"
SUBTASK_COMPLETION_FIRST = "基准子任务完成率（Benchmark Sub-task Completion Rate）"
MISS_RATE_FIRST = "漏报率（Miss Rate）"
EVIDENCE_COMPLETENESS_FIRST = "证据完整率（Evidence Completeness Rate）"
MEAN_E2E_RUNTIME_FIRST = "平均端到端净耗时（Mean End-to-End Runtime）"

# 正文后续出现
RECALL_GT = "基准阳性召回率"
SUBTASK_COMPLETION = "基准子任务完成率"
MISS_RATE = "漏报率"
EVIDENCE_COMPLETENESS = "证据完整率"
MEAN_E2E_RUNTIME = "平均端到端净耗时"

# 工作簿/表格列名（双语，中文在前）
RECALL_AT_GT_COL = RECALL_GT_FIRST
SUBTASK_COMPLETION_COL = SUBTASK_COMPLETION_FIRST
MISS_RATE_COL = MISS_RATE_FIRST
EVIDENCE_COMPLETENESS_COL = EVIDENCE_COMPLETENESS_FIRST
MEAN_E2E_RUNTIME_COL = MEAN_E2E_RUNTIME_FIRST
HITS_AT_GT_FRACTION_COL = "Hits@GT/|GT|（命中/基准阳性数）"
SUBTASK_FRACTION_COL = "Completed/|T|（完成项/基准任务数）"
EVIDENCE_FRACTION_COL = "Complete/Executed（完整证据/已执行数）"

FIVE_METRICS_FIRST = (
    f"{RECALL_GT_FIRST}、{SUBTASK_COMPLETION_FIRST}、{MISS_RATE_FIRST}、"
    f"{EVIDENCE_COMPLETENESS_FIRST}和{MEAN_E2E_RUNTIME_FIRST}"
)
FIVE_METRICS_CN = (
    f"{RECALL_GT}、{SUBTASK_COMPLETION}、{MISS_RATE}、"
    f"{EVIDENCE_COMPLETENESS}和{MEAN_E2E_RUNTIME}"
)

# strict JSON 数据集仍使用旧键名（仅同步数值，不改 JSON 结构）
JSON_RECALL_KEY = "基准阳性召回率（Vulnerability Recall）"
JSON_SUBTASK_KEY = "基准子任务完成率（Benchmark Sub-task Completion Rate）"
JSON_LATENCY_KEY = "平均端到端净耗时（Mean End-to-End Runtime）"
JSON_MISS_KEY = "漏报率（Miss Rate）"

# 向后兼容别名（旧代码/旧表头 → 新列名）
LEGACY_TO_CANONICAL: dict[str, str] = {
    "漏洞检出率": RECALL_GT,
    "Recall@GT（基准阳性召回率）": RECALL_AT_GT_COL,
    "基准阳性召回率（Recall@GT）": RECALL_AT_GT_COL,
    "任务完成率": SUBTASK_COMPLETION,
    "任务推进率": SUBTASK_COMPLETION,
    "任务推进率（Progress Rate）": SUBTASK_COMPLETION_COL,
    "Coverage（覆盖率）": SUBTASK_COMPLETION_COL,
    "基准项执行覆盖率": SUBTASK_COMPLETION_COL,
    "有效证据率": EVIDENCE_COMPLETENESS,
    "可审计证据率": EVIDENCE_COMPLETENESS,
    "可审计证据率（Auditable Evidence Rate）": EVIDENCE_COMPLETENESS_COL,
    "证据完备率": EVIDENCE_COMPLETENESS,
    "平均验证耗时": MEAN_E2E_RUNTIME,
    "平均时延": MEAN_E2E_RUNTIME,
    "平均时延（Avg. Latency）": MEAN_E2E_RUNTIME_COL,
    "Avg. Latency（平均验证耗时）": MEAN_E2E_RUNTIME_COL,
    "漏报率": MISS_RATE,
    "Covered/|T|（推进项/基准任务数）": SUBTASK_FRACTION_COL,
    "Covered/|T|（覆盖项/基准任务数）": SUBTASK_FRACTION_COL,
    "Audited/Executed（可审计/已执行数）": EVIDENCE_FRACTION_COL,
}

# 旧常量名兼容（逐步淘汰）
PROGRESS_RATE_FIRST = SUBTASK_COMPLETION_FIRST
PROGRESS_RATE = SUBTASK_COMPLETION
PROGRESS_RATE_COL = SUBTASK_COMPLETION_COL
PROGRESS_FRACTION_COL = SUBTASK_FRACTION_COL
AUDITABLE_EVIDENCE_FIRST = EVIDENCE_COMPLETENESS_FIRST
AUDITABLE_EVIDENCE = EVIDENCE_COMPLETENESS
AUDITABLE_EVIDENCE_COL = EVIDENCE_COMPLETENESS_COL
AUDITABLE_FRACTION_COL = EVIDENCE_FRACTION_COL
AVG_LATENCY_FIRST = MEAN_E2E_RUNTIME_FIRST
AVG_LATENCY = MEAN_E2E_RUNTIME
AVG_LATENCY_COL = MEAN_E2E_RUNTIME_COL
FOUR_METRICS_FIRST = FIVE_METRICS_FIRST
FOUR_METRICS_CN = FIVE_METRICS_CN

# L5 证据完整归档（自洽表述，不依赖读者已知 L4）
L5_COMPLETE_ARCHIVE_SHORT = (
    "L5 完整归档：执行留痕、结构化结果、可复核实质材料、文件制品与审计记录齐备"
)
L5_COMPLETE_ARCHIVE_PROSE = (
    "L5 完整归档指单条 PoC 同时满足：（1）非空执行留痕与结构化结果；"
    "（2）可复核实质材料（协议响应摘录、日志正文或制品路径），风险判定不得仅依赖 trace_id；"
    "（3）可离线检查的 poc_run 文件制品；（4）审计记录（复核状态或平台 trace 关联）。"
)
L5_COMPLETE_ARCHIVE_EN = (
    "L5-complete: execution trace, structured result, substantive auditable material, "
    "archived poc_run artifact, and audit record (review state or platform trace)."
)

# 论文正文表号（v4_0612 等同结构稿；勿与 Excel 工作簿 sheet 名混用）
PAPER_TABLE_EVIDENCE_LEVELS = "表2"  # 证据链等级
PAPER_TABLE_CLOSED_LOOP = "表3"  # PoC 验证闭环统计
PAPER_TABLE_ABLATION = "表4"  # 消融实验
PAPER_TABLE_STRATEGY = "表5"  # 候选选择策略
PAPER_TABLE_MODEL = "表6"  # 大模型对比
PAPER_FIG_BASELINE = "图4"  # PentestGPT / Multi-Agent / EDVV 四指标对比

# Agent 层证据完整率出现的正文位置
PAPER_EVIDENCE_COMPLETENESS_LOCATIONS = f"{PAPER_TABLE_ABLATION}、{PAPER_TABLE_MODEL}及{PAPER_FIG_BASELINE}"

# 工作簿 sheet 名（仅脚本/审计内部使用，勿写入论文正文）
WORKBOOK_SHEET_CLOSED_LOOP = "表6_PoC命中成功漏报"
WORKBOOK_SHEET_ABLATION = "表7_智能体消融"
WORKBOOK_SHEET_MODEL = "表8_模型对比"
WORKBOOK_SHEET_PLATFORM = "表10_平台能力对比"

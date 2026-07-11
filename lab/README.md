# 实验数据采集与论文结果生成

**目标**：证明平台不是概念设计，而是能在复杂车端攻击面下完成**自动化、可控、可复现**的漏洞验证。

运行结束后你将直接得到：

| 产出 | 路径 | 论文用途 |
|------|------|----------|
| **论文总表（主交付）** | `lab/论文实验数据汇总.xlsx` | 表1–5、表8、安全控制、典型案例 |
| 各环境明细 Excel | `lab/evidence/<TARGET>/实验数据统计表.xlsx` | 单台设备附录 |
| Global vs Agent 对比 | `lab/evidence/<TARGET>/comparison.json` | 表8 方法优势 |
| 模型对比 | `lab/evidence/<TARGET>/model_comparison.json` | 多模型效率/检出/Token |
| PoC 覆盖 | `lab/evidence/poc_coverage.json` | 表1 |
| 扫描明细 | `lab/evidence/<TARGET>/scan_results.json` | 表2 |
| Agent 编排 | `lab/evidence/<TARGET>/agent_orchestration.json` | 表3 |
| CAN 记录 | `lab/evidence/REAL-CAR-01/can_test_records.csv` | 表4 |
| 证据 JSON | `lab/evidence/<TARGET>/poc_runs/`、`agent_runs/` | 可追溯归档 |

---

## 目录结构（精简后）

```
lab/
├── README.md                      # 本文件：完整实验步骤
├── experiment_config.full.json    # 实验配置模板（复制后填写）
├── run_full_experiment.sh         # ★ 一键入口
├── run_full_experiment.py         # 逐 target 编排
├── run_experiment.py              # Global 批量扫描
├── run_model_comparison.py        # 多模型 Agent
├── compare_global_vs_agent.py     # Global vs Agent 对比（表8）
├── build_experiment_workbook.py   # 单 target Excel
├── build_paper_workbook.py        # 论文总表合并
├── run_ivi_new_batch.py           # IVI 原厂 PoC
├── collect_can_passive.sh         # CAN 被动采集
├── mock_vehicle_services.py       # Mock 正样本服务
├── can_test_records.template.csv  # CAN 记录模板
├── ground_truth/                  # Mock 标准答案（可选）
└── evidence/                      # 运行后自动生成
```

---

## 实验设计说明

### 环境矩阵（5 套，可按时间裁剪）

| target_id | 环境 | 作用 |
|-----------|------|------|
| `MOCK-LOCAL` | 本地 Mock | 可控正样本 + **Ground Truth** |
| `VM-01` | 虚拟机 | 正样本/误报对照 |
| `IVI-01` / `IVI-02` | 车机 | 真实 IVI 适配验证 |
| `REAL-CAR-01` | 实车/台架 | CAN + USB + 典型案例 |

### 每个环境的测试单元

```
同一台设备 T：
  ① Global 批量扫描（无 Agent）→ 基线：适用 PoC 数、执行覆盖率、耗时、检出
  ② Agent × 多模型            → 对比：编排效率、检出、反思重入、Token
  ③ （可选）IVI 原厂 PoC、CAN 采集
```

**Agent 性能参照基准 = 同一设备上的 Global 扫描**，不是 Mock，也不是全库 PoC 总数。  
覆盖率分母应使用**该设备上被自动筛选为适用的 PoC 数**，即 `scan_results.json` / `scan_baseline_summary.json` 中的 `global_applicable_poc_count`。  
**IVI / 实车 / VM**：`server/pocs/new/` 与主库 PoC **同一次 Global 扫描**写入 `scan_results.json`（字段 `poc_origin`: `main` | `new`）；`run_ivi_new_batch.py` 仅在 `auto_select: false` 时作为遗留独立批次，论文表 2 以 Global 为准。  
**实车 `real_car`**：默认 `max_coverage`（`selector.max_coverage: true`），凡目标已具备之必需参数（`target_ip` / `can_interface` / `bluetooth_mac` 等）满足的 PoC 均纳入，**不依赖 ADB**；缺 `expected_usb_serial` 的 USB 座舱脚本会自动排除。可设 `disable_usb_adb_probe: true` 避免误探测本机 adb。  
表8 **主指标**（论文优先引用）：`gt_recall` / `paper_primary_recall`（Mock 使用 `lab/ground_truth/<TARGET>.json` 作分母）。
辅助指标：`poc_reduction_percent`（定向执行效率）、`agent_efficiency_score`（GT 召回 × 减负系数）。
参考指标：`agent_finding_recall_vs_global`（以 Global 检出为分母，**不代表真值**，仅作工程对照）。

Agent 侦察已默认：**candidate_ports 全口扫描** + **复用 Global `scan_results.json` 种子** + 决策失败时 **启发式攻击计划回退**。
决策阶段自动注入：**端口↔PoC 映射** + **poc_coverage 元数据表**（protocol / required_params / profiles）+ **Global 已检出优先复验列表**。
表8中的严格 Agent 执行覆盖率按 `baseline_overlap_count / global_executed_poc_count` 计算；Agent 额外执行的 PoC 单独统计为 `agent_extra_execution_count`，不计入覆盖率。

Mock 额外作用：提供可复现 **Ground Truth**，用于计算检出召回率（`gt_recall`）。

### 模型变体（默认 6 个，可裁剪）

| variant_id | 说明 |
|------------|------|
| `QWEN-PLUS` | 千问均衡 |
| `QWEN-MAX` | 千问质量优先 |
| `DEEPSEEK` | DeepSeek chat |
| `ZHIPU` | 智谱 GLM |
| `MINIMAX` | MiniMax Text |
| `GPT` | OpenAI GPT |

### 当前脚本默认输出的关键指标

- Global 基线：`global_applicable_poc_count`、`global_completed_poc_count`、`global_execution_coverage_ratio`、`global_elapsed_seconds`、`global_vulnerable_count`
- Agent 执行：`planned_poc_count`、`executed_poc_count`、`agent_execution_coverage_vs_global`、`finding_count`、`reflection_reentry_count`
- Agent 对 Global 漏洞检出：`finding_overlap_with_global`、`agent_finding_recall_vs_global`、`agent_finding_precision_vs_global`
- 人工确认：`requires_human_review`、`verification_status`、`manual_review_pending_count`
- 人工等待时间：`manual_review_wait_seconds` 单独记录，**不计入** `elapsed_seconds`
- Agent LLM 消耗：`llm_call_count`、`prompt_tokens`、`completion_tokens`、`total_tokens`、`avg_llm_latency_ms`
- 效率：`findings_per_minute`、`executions_per_minute`、`tokens_per_finding`
- Mock GT：`global_gt_recall`、`gt_recall`
- Provider 调优：可通过 `llm_timeout_seconds`、`llm_connect_timeout_seconds` 调整兼容 OpenAI 接口的超时；MiniMax 建议中国区使用 `https://api.minimaxi.com/v1`

---

## 完整实验步骤

### 第 0 步：安装依赖

```bash
cd /path/to/autosec-guard---icv-vulnerability-scanner
pip install -r server/requirements.txt openpyxl requests
```

### 第 1 步：创建本地配置（含 API Key，勿提交 Git）

```bash
cp lab/experiment_config.full.json lab/experiment_config.local.json
```

编辑 `lab/experiment_config.local.json`，替换：

| 占位符 | 说明 |
|--------|------|
| `REPLACE_VM_IP` | 虚拟机 IP |
| `REPLACE_IVI_01_IP` / `REPLACE_IVI_02_IP` | 车机 IP |
| `REPLACE_IVI_01_USB_SERIAL` 等 | **可选**；实验要求仅插 1 台 USB 车机/设备，多台时不会跑 USB ADB PoC |
| `REPLACE_REAL_CAR_IVI_IP` | 实车 IVI IP |
| `REPLACE_REAL_CAR_USB_SERIAL` | 实车 USB serial |
| `YOUR_DASHSCOPE_API_KEY` | 千问 API Key |
| `YOUR_DEEPSEEK_API_KEY` | DeepSeek API Key |
| `YOUR_ZHIPU_API_KEY` | 智谱 API Key |
| `YOUR_MINIMAX_API_KEY` | MiniMax API Key |
| `YOUR_OPENAI_API_KEY` | OpenAI API Key |

不需要的环境：在 `experiment_run_order` 中删除对应 ID，或用 `--target-id` 只跑部分。

### 第 2 步：启动平台

**终端 A — Mock 服务**（跑 `MOCK-LOCAL` 时必须，覆盖 50+ TCP / 4 UDP 端口）：

```bash
python3 lab/mock_vehicle_services.py
# 查看全部 mock 端口：python3 lab/mock_vehicle_services.py --list
# 停止旧实例：python3 lab/mock_vehicle_services.py --stop
```

启动时会**自动停止**上一次未退干净的 mock 进程；`3000`/`5002` 留给前端与后端，mock 不会抢占。

**终端 B — 后端**（全程保持）：

```bash
cd server && python3 server.py
```

验证：

```bash
curl http://127.0.0.1:5002/health
```

**REAL-CAR-01 额外（CAN）：**

平台 PoC 走 **python-can + PCAN 驱动**（默认接口名 `PCAN_USBBUS1`），**不需要** `ip link set can0`。

```bash
# 1. 安装 PEAK PCAN 驱动 + pip install python-can
# 2. 在 experiment_config.local.json 中设置：
#    "can_interface": "PCAN_USBBUS1"
#    "can_bitrate": 500000   （与实车总线一致，常见 500k 或 250k）

# 3. 实车 CAN 采集（平台 API 嗅探；candump 仅 SocketCAN 可用）
bash lab/collect_can_passive.sh PCAN_USBBUS1 15
```

若你用的是 **Linux SocketCAN**（`can0` / `vcan0`），才需要：

```bash
sudo ip link set can0 up type can bitrate 500000
bash lab/collect_can_passive.sh can0 15
```

### 第 3 步：一键执行完整实验

```bash
bash lab/run_full_experiment.sh
```

脚本自动按顺序执行：

1. 统计 PoC 插件库覆盖 → `lab/evidence/poc_coverage.json`
2. 对每个 target：
   - Global 扫描（无 Agent）
   - IVI 原厂 PoC（车机/实车）
  - Agent × 多模型
   - CAN 被动采集（仅 REAL-CAR-01）
   - 生成 Global vs Agent 对比 → `comparison.json`
   - 生成单 target Excel
3. 合并论文总表 → **`lab/论文实验数据汇总.xlsx`**

### 第 4 步：Mock Ground Truth（建议，约 5 分钟）

Global 跑完 MOCK-LOCAL 后：

```bash
# 查看自动生成的 GT 草稿
cat lab/evidence/MOCK-LOCAL/ground_truth_hint.json

# 人工确认后保存为标准答案
cp lab/ground_truth/MOCK-LOCAL.template.json lab/ground_truth/MOCK-LOCAL.json
# 编辑 positive_pocs 列表

# 重新生成对比（含 gt_recall）
python3 lab/compare_global_vs_agent.py \
  --target-dir lab/evidence/MOCK-LOCAL --target-id MOCK-LOCAL
python3 lab/build_paper_workbook.py
```

### 第 5 步：截图归档（论文表9）

每个 target 建议保存：

- Global 扫描完成界面 / `scan_results.json` 路径
- Agent Scan 日志界面
- 1–2 条 PoC 证据 JSON（`poc_runs/` 内）
- 实车：`adb devices` 截图、`can_passive.log`

放入 `lab/evidence/<TARGET>/screenshots/`（需手动创建）。

### 第 6 步：检查交付物

```bash
ls -la lab/论文实验数据汇总.xlsx
ls lab/evidence/*/comparison.json
ls lab/evidence/*/model_comparison.json
```

确认 Excel 中含：

- [x] 表1 PoC 覆盖
- [x] 表2 扫描执行结果
- [x] 表3 多 Agent 编排
- [x] 表4 CAN（实车）
- [x] 表5 模型对比
- [x] 表8 Global 与 Agent 对比
- [x] 安全拦截明细
- [x] 典型案例

---

## 常用裁剪命令

**只跑 Mock + 实车（一晚方案）：**

```bash
bash lab/run_full_experiment.sh \
  --target-id MOCK-LOCAL \
  --target-id REAL-CAR-01
```

**只跑 2 个模型（省时间）：**

```bash
bash lab/run_full_experiment.sh \
  --target-id IVI-01 \
  --variant-id QWEN-PLUS \
  --variant-id DEEPSEEK
```

**Global 已跑过，只补 Agent：**

```bash
bash lab/run_full_experiment.sh --target-id IVI-01 --skip-global
```

**推荐：单 target 用 `run_experiment` 一条命令（Global + 多模型 Agent + 表8）**

```bash
CONFIG=lab/experiment_config.local.json

# 指定 --target-id 时，输出目录自动落到 lab/evidence/MOCK-LOCAL/
python3 lab/run_experiment.py --config $CONFIG --target-id MOCK-LOCAL

# 只跑部分模型
python3 lab/run_experiment.py --config $CONFIG --target-id MOCK-LOCAL \
  --variant-id QWEN-PLUS --variant-id QWEN-MAX

# 已有 Global，只补 Agent（目录里需已有 scan_results.json）
python3 lab/run_experiment.py --config $CONFIG --target-id MOCK-LOCAL --skip-global
```

说明：`agent_tasks` 为空时，会自动从 `model_comparison.variants` × `scan_targets[].agent_profile` 生成 Agent 任务，并写入 `model_comparison.json`、`comparison.json`（含 `gt_recall`）。

实验默认 **`skip_assessment_report: true`**（不调用 Assessment Agent 生成长文安全报告，显著省时）；指标仍来自 `findings` / `structured.execution`。UI 完整渗透测试不受影响。

**分步（与一键等价）：**

```bash
CONFIG=lab/experiment_config.local.json
OUT=lab/evidence/IVI-01

python3 lab/run_experiment.py --config $CONFIG --output-dir $OUT --target-id IVI-01
python3 lab/build_experiment_workbook.py --experiment-dir $OUT --output $OUT/实验数据统计表.xlsx
python3 lab/build_paper_workbook.py
```

---

## 论文 4 张核心表与数据对应

| 论文表 | Excel 工作表 | 数据来源 |
|--------|-------------|----------|
| 表1 PoC 攻击面覆盖 | `表1_PoC覆盖情况` | `poc_coverage.json` |
| 表2 扫描执行结果 | `表2_扫描执行结果` | 各 target `scan_results.json` |
| 表3 多 Agent 编排 | `表3_多Agent编排` | 各 target `agent_orchestration.json` |
| 表4 CAN 测试 | `表4_CAN网关联动` | `REAL-CAR-01/can_test_records.csv` |

补充：表5 模型对比、表8 Global vs Agent、安全控制、典型案例均在 `论文实验数据汇总.xlsx` 中。

---

## 指标说明（写论文用）

| 指标 | 含义 | 计算 |
|------|------|------|
| Global 总耗时 | 无 Agent 基线时间 | `scan_results` 耗时求和 |
| Agent 总耗时 | 多 Agent 编排时间 | `model_comparison.variants[].elapsed_seconds` |
| PoC 缩减率 | Agent 少跑多少 PoC | `comparison.json` 的 `poc_reduction_percent` |
| 时间比 | Global/Agent 耗时比 | `time_ratio_global_over_agent` |
| Agent 执行覆盖率 | Agent 跑到多少 Global 已执行 PoC | `agent_execution_coverage_vs_global` |
| Agent 检出召回率（相对 Global） | Agent 复现了多少 Global 已检出的漏洞 | `agent_finding_recall_vs_global` |
| Agent 检出精度（相对 Global） | Agent 的检出里有多少与 Global 一致 | `agent_finding_precision_vs_global` |
| GT 召回 | Mock 上相对真值的检出召回 | `gt_recall`（需 `ground_truth/MOCK-LOCAL.json`） |
| 反思重入 | 闭环有效性 | `reflection_reentry_count` |
| 安全拦截 | 可控性 | `blocked=true` 的 PoC 数量 |

---

## CAN 测试（无分析仪）

论文表述用 **「CAN 总线接口/网关联动测试」**，勿写「CAN 分析仪联动」。

实车仅做低风险项：

- 被动 `candump`（15s）
- 1 条 UDS DefaultSession 探测
- 平台 `01_CAN_Bus_Sniff.py`
- fuzz/DoS 记 `blocked_by_safety=true`（证明安全可控）

单独执行：

```bash
# PCAN-USB（macOS / Windows，推荐）
bash lab/collect_can_passive.sh PCAN_USBBUS1 15

# SocketCAN（Linux can0）
bash lab/collect_can_passive.sh can0 15
```

---

## 故障排查

| 现象 | 处理 |
|------|------|
| Agent Gate 拦截、0 PoC | `adb devices` 须**恰好 1 台** USB 设备；多台时请拔掉多余线，serial 可留空 |
| Mock 扫描 0 检出 | 确认 `mock_vehicle_services.py` 在运行 |
| Mock 大量 `Address already in use` | 执行 `python3 lab/mock_vehicle_services.py --stop` 后重新启动（新版默认会自动清理旧实例） |
| DeepSeek 报错 | 检查 `base_url` 和 API Key；模型名用 `deepseek-chat` |
| CAN 0 帧 | 检查 `ip link`、bitrate、接线 |
| Excel 为空 | 确认 `lab/evidence/<TARGET>/scan_results.json` 存在后再跑 `build_paper_workbook.py` |

---

## 老师要求的 10 类数据覆盖

| # | 数据类别 | 本套件产出 |
|---|----------|-----------|
| 1 | PoC 插件库覆盖 | 表1 + `poc_coverage.json` |
| 2 | 扫描执行效率 | 表2 耗时列 |
| 3 | 漏洞检出结果 | 表2 `是否发现风险` + 证据 JSON |
| 4 | 多 Agent 编排 | 表3 + `model_comparison.json` |
| 5 | 安全控制 | 安全拦截明细 + `blocked` 字段 |
| 6 | CAN 联动 | 表4 |
| 7 | 边缘设备能力 | 各 target `edge_capabilities.json` |
| 8 | 对比实验 | 表8 `comparison.json` |
| 9 | 证据归档 | `poc_runs/`、`agent_runs/` + 截图 |
| 10 | 典型案例 | 典型案例工作表 |

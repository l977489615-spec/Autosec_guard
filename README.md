<div align="center">

# 🛡️ 智驭安盾
### SmartDrive Shield — 智能网联汽车漏洞扫描与安全评估平台

<p>
  <img src="https://img.shields.io/badge/版本-Current-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/静态%20PoC-70-green?style=flat-square" />
  <img src="https://img.shields.io/badge/攻击面类别-6-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/Agent%20Workflow-MCP%20%2B%20Qwen-purple?style=flat-square" />
  <img src="https://img.shields.io/badge/database-SQLite-informational?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square" />
</p>

**智驭安盾（SmartDrive Shield）** 是一个面向智能网联汽车（ICV）的漏洞验证、攻击面分析与结构化安全评估平台。  
它集成了 PoC 执行、风险控制、结果留痕、历史审计、Agent 协作扫描与边缘节点调度能力，适用于教学研究、实验室台架验证和授权安全测试场景。

</div>

---

## 📚 目录

- [🎯 你会得到什么](#-你会得到什么)
- [🚀 5 分钟快速上手](#-5-分钟快速上手)
- [🧭 第一次完整扫描（实战教程）](#-第一次完整扫描实战教程)
- [🧠 项目原理与架构设计](#-项目原理与架构设计)
- [✨ 核心亮点](#-核心亮点)
- [🌐 Edge Control 与边缘节点](#-edge-control-与边缘节点)
- [⚙️ 配置说明](#️-配置说明)
- [🔌 常用 API](#-常用-api)
- [🗂️ 项目目录结构](#️-项目目录结构)
- [❓ 常见问题](#-常见问题)
- [⚠️ 免责声明](#️-免责声明)
- [📄 License](#-license)

---

## 🎯 你会得到什么

**智驭安盾（SmartDrive Shield）** 是一个面向 ICV（智能网联汽车）安全验证的端到端平台：  
从 PoC 验证、风险拦截、结构化评估，到历史审计、Agent 协作扫描与 Edge 执行调度，提供一条完整工程链路。

它适合三类场景：

- 🔬 **实验室与台架验证**：快速复现实验并保留审计证据
- 🧪 **教学与研究**：按攻击面组织 PoC，便于演示与对比
- 🏭 **授权安全测试**：通过审批机制和边缘节点控制高风险动作

---

## 🚀 5 分钟快速上手

### 1) 启动后端（Flask API）

```bash
cd server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 server.py
```

### 2) 启动前端（Vite + React）

```bash
cd client
npm install
npm run dev
```

### 3) 访问与健康检查

- 前端控制台：`http://localhost:3000`
- 后端健康检查：`http://localhost:5002/api/health`

### 4) 可选：启用 Agent Scan

```bash
cd server
source .venv/bin/activate
python3 mcp_server.py
```

> ✅ 到这里，你已经可以进行 Manual / Global 扫描。  
> ✅ 仅当需要 `Agent Scan` 时才必须启动 MCP Server。

---

## 🧭 第一次完整扫描（实战教程）

下面是一条推荐路径，能让新用户 10-15 分钟掌握完整闭环。

### Step A — 登录并检查引擎连通

1. 进入 `Global Auto Scan`
2. 确认 Engine URL（默认 `http://localhost:5002`）
3. 点击连接测试，看到 `online`

### Step B — 配置目标参数

建议至少填写一个可用参数（推荐 `IP Address`），可选：

- `Bluetooth MAC`
- `CAN Interface`
- `Wi-Fi Interface`
- `RF Frequency`

### Step C — 执行全量扫描

点击 `EXECUTE FULL SCAN` 后系统会自动：

1. 做后端与目标连通检查
2. 进行 OS 指纹识别（可用时）
3. 按 PoC 元数据过滤可执行项
4. 实时输出日志与结果
5. 汇总风险并保存会话

### Step D — 处理高风险 PoC 审批

当命中高风险 PoC（如重启/破坏类），系统会弹出确认框：

- `Skip This PoC`：跳过
- `Confirm And Execute`：只确认当前项
- `Confirm For Rest Of Scan`：本轮后续高风险项自动通过

### Step E — 结果分析与沉淀

扫描完成后你可以：

- 查看漏洞明细、证据和错误原因
- 生成 AI 安全报告
- 在 `Scan History` 中检索历史会话
- 查看结构化评估（攻击路径 / 物理影响 / 修复建议）

---

## 🧠 项目原理与架构设计

### 1) 三层执行模型：UI → API → Runner

- **UI 层（client）**：参数收集、风险确认、可视化日志和报告
- **API 层（server）**：鉴权、参数归一化、调度、审计和持久化
- **Runner 层（poc_worker + sandbox_runner）**：PoC 沙箱执行与结果解析

### 2) 为什么需要 `run_poc_stream`

普通同步接口适合短任务；`run_poc_stream` 通过 SSE 逐行回传日志，解决：

- 大量 PoC 批量执行的“黑盒等待”
- 复杂 PoC 的调试可观测性
- 用户对执行过程的实时确认需求

### 3) 高风险防护链路

高风险 PoC 并不是“直接运行”，而是经过：

1. PoC 安全画像识别（`is_disruptive`、`destructive_level`）
2. 前端审批弹窗确认
3. 后端二次校验 `allow_disruptive`
4. 审计日志落库

这保证了“前端体验 + 后端强约束”的双保险。

### 4) 云边协同模型（Cloud + Edge）

- `cloud`：适合云主机可直接触达的目标
- `edge`：适合私网、实验网、带本地硬件依赖（CAN/BT/Wi-Fi Monitor/SDR）的目标

后端根据 PoC 能力需求给出推荐，并下发任务到边缘节点执行。

---

## ✨ 核心亮点

- 🛡️ **安全优先**：高风险 PoC 双重审批与审计留痕
- 🧱 **工程化执行**：SSE 实时日志 + 结构化结果 + 历史可追溯
- 🧠 **可扩展架构**：PoC 安全判定、执行参数归一化、认证逻辑已模块化
- 🌐 **云边一体**：在云端控制，在边缘执行，兼顾可达性与硬件能力
- 📚 **多场景覆盖**：Recon / Network / CAN / Wireless / Application / Advanced

---

## 🖼️ 系统截图

### Dashboard — 态势总览

<div align="center">
  <img src="assets/dashboard.png" width="92%" alt="Dashboard" />
</div>

### Scan Engine — 扫描引擎

<div align="center">
  <img src="assets/scan_engine.png" width="92%" alt="Scan Engine" />
</div>

### Agent Scan — 多 Agent 自主扫描

<div align="center">
  <img src="assets/agent_scan.png" width="92%" alt="Agent Scan" />
</div>

### PoC Database — 漏洞知识库

<div align="center">
  <img src="assets/poc_database.png" width="92%" alt="PoC Database" />
</div>

### Scan History — 扫描记录与审计

<div align="center">
  <img src="assets/scan_history.png" width="92%" alt="Scan History" />
</div>

---

## 🌐 Edge Control 与边缘节点

### 为什么需要 Edge

云端服务通常无法直接访问：

- USB 挂载
- PCAN / SocketCAN
- 本地蓝牙适配器
- Monitor 模式 Wi-Fi 网卡
- HackRF / SDR
- 私网中的目标车机

因此 Edge Agent 负责“贴近设备侧”执行，控制面仍留在云端。

### Edge Agent 标准接入流程

1. 启动云端后端 `server.py`
2. 构建 edge runtime（优先 Nuitka，兼容 PyInstaller）
3. 在前端生成一次性 enrollment 命令
4. 边缘主机执行部署命令完成注册
5. 启动 daemon 轮询任务并回传结果

示例：

```bash
curl -fsSL "https://your-cloud.example.com/api/edge/install.sh?enrollment_token=<ONE_TIME_TOKEN>" | bash
$HOME/.autosec-edge/autosec-edge --edge-api https://your-cloud.example.com --daemon
```

---

## ⚙️ 配置说明

`server/config.py` 会自动加载：

- 项目根目录 `.env` / `.env.local`
- `server/.env` / `server/.env.local`

常用环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `AUTOSEC_SECRET_KEY` | 自动生成 | JWT 签名密钥 |
| `AUTOSEC_DB_URI` | 本地 SQLite | 数据库连接串 |
| `AUTOSEC_API` | `http://localhost:5002` | 主 API 地址 |
| `MCP_SERVER` | `http://localhost:5003` | MCP Server 地址 |
| `AUTOSEC_EDGE_RUNTIME_PATH` | `build/edge_runtime/autosec-edge` | edge runtime 文件或目录 |
| `AUTOSEC_EDGE_BUILD_DIR` | `build/edge_runtime` | edge 构建输出目录 |
| `AUTOSEC_HOST` | `0.0.0.0` | Flask 监听地址 |
| `AUTOSEC_PORT` | `5002` | Flask 端口 |
| `AUTOSEC_DEBUG` | `false` | Flask debug 开关 |

推荐本地配置：

```env
AUTOSEC_SECRET_KEY=replace-with-a-long-random-string
AUTOSEC_DB_URI=sqlite:///server/autosec.db
AUTOSEC_API=http://localhost:5002
MCP_SERVER=http://localhost:5003
AUTOSEC_EDGE_BUILD_DIR=build/edge_runtime
AUTOSEC_PORT=5002
AUTOSEC_DEBUG=false
```

补充说明：

- AI 参数由用户在前端 `Profile Settings` 单独配置并加密存储
- `server/autosec.db` 作为本地开发库，建议不纳入 Git，按需备份到 `server/backups/`

---

## 🔌 常用 API

### 基础执行

- `GET /api/health`
- `GET /api/list_pocs`
- `GET /api/poc-registry`
- `POST /api/fingerprint`
- `POST /api/run_poc`
- `POST /api/run_poc_stream`

### 评估与报告

- `POST /api/report/generate`
- `POST /api/attack-graph/generate`
- `POST /api/physical-impact/assess`
- `POST /api/remediation/simulate`
- `POST /api/report/structured`

### 历史与审计

- `POST /api/save_session`
- `GET /api/history`
- `DELETE /api/history/<id>`
- `POST /api/history/delete-batch`
- `GET /api/session-artifacts/<session_id>`
- `GET /api/supervisor-metrics`

### Agent 与 Edge

- `POST /api/topology`
- `POST /api/adaptive-context`
- `POST /api/agent-scan`
- `POST /api/edge/register`
- `POST /api/edge/heartbeat`
- `GET /api/edge/agents`
- `POST /api/edge/enrollment-tokens`
- `GET /api/edge/install.sh`
- `POST /api/edge/tasks`
- `GET /api/edge/tasks/next`
- `POST /api/edge/tasks/<task_id>/result`

---

## 🗂️ 项目目录结构

```text
.
├── client/
│   ├── components/              # UI 页面与主要交互逻辑
│   ├── data/                    # 数据层导出（如 POC_DATABASE）
│   ├── services/                # API 调用与前端服务
│   ├── constants.ts             # 常量定义（逐步轻量化）
│   └── vite.config.ts
├── server/
│   ├── server.py                # 主 API 入口（保持兼容）
│   ├── config.py                # 配置加载与运行参数
│   ├── auth_service.py          # Bearer -> User 解析
│   ├── poc_security.py          # PoC 安全画像与审批判定
│   ├── poc_execution_service.py # 执行参数归一化与 target 解析
│   ├── poc_worker.py            # 执行计划与 Runner 调度
│   ├── sandbox_runner.py        # 沙箱执行器
│   ├── edge_*.py                # 云边调度能力模块
│   ├── benchmarks/
│   └── pocs/
├── docs/
│   └── internal/
├── tools/
│   └── legacy/
├── build/
│   └── edge_runtime/
├── assets/
└── README.md
```

---

## ❓ 常见问题

### 1. `/api/health` 正常，但 Edge 注册 404

通常是旧进程占用了端口。请重启并确认运行的是当前仓库的：

```bash
python3 server/server.py
```

### 2. 为什么云端扫不到客户内网目标

云端不在客户私网内。对实验网/车间网/台架网目标，请走 Edge 执行。

### 3. 高风险 PoC 为什么仍可能被拒绝

系统采用前端确认 + 后端强校验双重机制。请确认请求参数中包含 `allow_disruptive=true`。

### 4. Agent Scan 不可用

请检查：

- `server/mcp_server.py` 是否启动
- 用户是否在 `Profile Settings` 中配置了模型参数
- 模型接口网络是否可达

### 5. 某些 PoC 无法直接运行

可能依赖特定硬件或权限（CAN、蓝牙、Wi-Fi Monitor、SDR 等）。建议迁移到具备能力的边缘节点执行。

---

## ⚠️ 免责声明

本项目仅可用于：

- 经授权的安全测试
- 实验室台架验证
- 教学、研究、演示与方法评估

禁止将其用于未授权目标、生产车辆或任何违反法律法规的场景。  
高风险 PoC 即使在实验环境中也应在审批、隔离和回滚预案完备的前提下执行。

---

## 📄 License

本项目基于 [MIT License](LICENSE) 开源发布。

<div align="center">
  智驭安盾 · SmartDrive Shield · Built for ICV Security Research
</div>

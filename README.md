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

- [项目简介](#-项目简介)
- [功能概览](#-功能概览)
- [系统截图](#-系统截图)
- [快速开始](#-快速开始)
- [运行环境](#-运行环境)
- [配置说明](#-配置说明)
- [启动方式](#-启动方式)
- [使用说明](#-使用说明)
- [Edge Control 与边缘节点](#-edge-control-与边缘节点)
- [部署提示](#-部署提示)
- [常用 API](#-常用-api)
- [项目目录结构](#-项目目录结构)
- [常见问题](#-常见问题)
- [免责声明](#-免责声明)
- [License](#-license)

---

## 🚗 项目简介

智驭安盾用于帮助研究人员、安全工程师和实验室用户完成智能网联汽车相关目标的漏洞验证与安全评估。平台提供：

- Web 控制台
- 本地 PoC 执行引擎
- 结构化安全评估能力
- 历史会话与审计记录
- 基于 MCP 的 Agent 扫描链路
- 面向本地硬件环境的边缘节点调度能力

平台支持从单个 PoC 调试，到批量扫描、结构化报告生成，再到带有边缘能力匹配的执行任务编排。

---

## ✨ 功能概览

### 1. 漏洞验证能力

当前仓库包含多类 ICV 相关 PoC，覆盖以下方向：

- Reconnaissance：目标发现、端口与服务探测
- Network：ADB、SSH、Telnet、MQTT、RTSP、SOME/IP 等
- CAN / Diagnostics：CAN 注入、重放、UDS、OBD 诊断
- Wireless：Wi-Fi、Bluetooth、BLE、QNX Qnet 等
- Application：AirPlay、CarPlay、USB、WebView、HiQnet 等
- Advanced：OTA、GPS、TPMS、V2X、固件更新等

### 2. 三种主要使用模式

- **Global Auto Scan**
  - 根据输入参数自动筛选适用 PoC 并批量执行
- **Manual Diagnostic**
  - 针对单个 PoC 做定向验证、复测与调试
- **Agent Scan**
  - 基于 MCP + LLM 的多阶段自主扫描模式

### 3. 风险控制与结果沉淀

平台支持：

- PoC 沙箱执行
- 高风险 PoC 审批拦截
- 扫描日志与结果留痕
- 历史会话保存
- 攻击路径、物理影响、缓解建议等结构化评估
- Benchmark 回归评分
- Edge 能力匹配与任务下发

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

## ⚡ 快速开始

### 最短启动路径

```bash
# 1. 安装前端依赖
cd client
npm install

# 2. 安装后端依赖
cd ../server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. 启动后端
python3 server.py

# 4. 启动前端
cd ../client
npm run dev
```

启动完成后访问：

- 前端：`http://localhost:3000`
- 后端健康检查：`http://localhost:5002/api/health`

### Agent 模式额外要求

如果需要使用 `Agent Scan`，还需要启动 MCP Server：

```bash
cd server
source .venv/bin/activate
python3 mcp_server.py
```

模型配置改为由每个用户在前端 `Profile Settings` 中单独填写。

---

## 🧰 运行环境

### 基础要求

- Node.js 18+
- Python 3.10+（建议）
- Linux 或 macOS

### Python 依赖

见 `server/requirements.txt`，核心依赖包括：

- `flask`
- `flask-cors`
- `flask-sqlalchemy`
- `scapy`
- `python-can`
- `paramiko`
- `bcrypt`
- `PyJWT`
- `requests`
- `openai`

说明：默认数据库为 SQLite。

### 可选外部能力

以下能力按需启用：

- AI 报告 / Agent 模式：需要用户在前端填写自己的 OpenAI-compatible API 配置
- CAN / Bluetooth / Wi-Fi / SDR 相关 PoC：需要本地硬件、驱动与系统权限
- 边缘执行能力：需要至少一个可注册的 edge agent

---

## ⚙️ 配置说明

项目通过 `server/config.py` 自动加载以下环境文件：

- 项目根目录 `.env`
- 项目根目录 `.env.local`
- `server/.env`
- `server/.env.local`

常用环境变量如下：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `AUTOSEC_SECRET_KEY` | 自动生成 | JWT 签名密钥 |
| `AUTOSEC_DB_URI` | 本地 SQLite | 数据库连接串 |
| `AUTOSEC_API` | `http://localhost:5002` | 主 Flask API 地址 |
| `MCP_SERVER` | `http://localhost:5003` | MCP 服务地址 |
| `AUTOSEC_EDGE_RUNTIME_PATH` | `build/edge_runtime/autosec-edge` | edge runtime 文件或目录 |
| `AUTOSEC_EDGE_BUILD_DIR` | `build/edge_runtime` | edge 构建输出目录 |
| `AUTOSEC_HOST` | `0.0.0.0` | Flask 监听地址 |
| `AUTOSEC_PORT` | `5002` | Flask 端口 |
| `AUTOSEC_DEBUG` | `false` | Flask debug 开关 |

### 推荐的本地开发配置示例

```env
AUTOSEC_SECRET_KEY=replace-with-a-long-random-string
AUTOSEC_DB_URI=sqlite:///server/autosec.db
AUTOSEC_API=http://localhost:5002
MCP_SERVER=http://localhost:5003
AUTOSEC_EDGE_BUILD_DIR=build/edge_runtime
AUTOSEC_PORT=5002
AUTOSEC_DEBUG=false
```

说明：

- 生产环境使用前端生成的一次性 enrollment token，不要求终端用户访问 `.env`
- `AUTOSEC_EDGE_RUNTIME_PATH` 用于云端分发已构建好的 edge runtime
- AI 配置不再放在服务端 `.env`，由用户在前端资料页填写，并以加密形式保存在服务端数据库中

---

## 🚀 启动方式

### 1. 启动基础扫描模式

适用于：

- PoC 列表浏览
- 手动单项验证
- 批量扫描
- 历史记录与结构化评估

```bash
# 终端 1：启动 Flask API
cd server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 server.py

# 终端 2：启动前端
cd client
npm install
npm run dev
```

### 2. 启动 Agent 模式

适用于需要多阶段自主扫描的场景：

```bash
# 终端 1：Flask API
cd server
source .venv/bin/activate
python3 server.py

# 终端 2：MCP Server
cd server
source .venv/bin/activate
python3 mcp_server.py

# 终端 3：前端
cd client
npm run dev
```

如果用户没有在前端配置自己的 AI 参数，Agent 模式与 AI 报告会不可用，但基础扫描仍可正常使用。

---

## 📖 使用说明

### 1. 登录与账号

- 首次注册的用户会自动成为管理员
- 普通用户默认只能查看自己的扫描历史
- 管理员可管理用户与全局历史

### 2. Global Auto Scan

适合批量筛选并执行适用 PoC。

推荐填写：

- `IP Address`
- `Bluetooth MAC`
- `CAN Interface`
- `Wi-Fi Interface`
- `RF Frequency`

系统会自动：

1. 检查后端状态
2. 进行目标 OS 指纹识别
3. 根据参数和 PoC 元数据筛选可执行项
4. 执行 PoC 并实时回显日志
5. 汇总风险与结构化评估结果
6. 保存会话到历史记录

### 3. Manual Diagnostic

适合单个 PoC 的调试与复测。

你可以：

- 查看 PoC 源码
- 手动输入参数
- 直接发起 PoC 验证
- 查看日志、证据、错误和结果

如果目标 PoC 被识别为高风险，系统会阻止执行并返回审批提示。

### 4. Agent Scan

适合目标较复杂、需要先侦察再规划与执行的场景。

建议至少提供：

- `target_ip`
- 可选的 `can_interface`
- 可选的 `bluetooth_mac`
- 可选的 `wifi_interface`

支持：

- 单阶段调试
- 全流程运行
- 从指定阶段恢复继续
- 持久化 `phase_records`、`findings` 和结构化状态

---

## 🌐 Edge Control 与边缘节点

### 为什么需要边缘节点

如果系统运行在云端或普通开发主机上，后端默认无法直接访问下列本地能力：

- USB 挂载
- PCAN / SocketCAN
- 本地蓝牙适配器
- Monitor 模式 Wi-Fi 网卡
- HackRF / SDR
- 仅内网可达的车机或测试目标

这类能力适合通过 **Edge Agent** 提供。  
Edge Agent 运行在本地 Linux 主机、实验设备或工控机上，负责：

- 探测本地硬件能力
- 注册到控制面
- 接收边缘执行任务
- 本地执行 PoC
- 回传日志与结构化结果

### Edge Agent 注册步骤

#### 1. 启动云端后端

```bash
cd server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 server.py
```

#### 2. 构建 edge runtime

优先使用 Nuitka：

```bash
cd server
source .venv/bin/activate
pip install nuitka
python3 build_nuitka.py
```

兼容旧环境时仍可使用 PyInstaller：

```bash
cd server
source .venv/bin/activate
pip install pyinstaller
python3 build_edge_runtime.py
```

默认产物目录：

```text
build/edge_runtime/
```

#### 3. 在前端生成一次性部署命令

登录 Web UI 后，进入 `Edge Control Plane`：

- 填写节点标签与有效期
- 点击“生成部署命令”
- 把生成的一条 `curl ... | bash` 命令发给边缘端用户

#### 4. 边缘端用户执行部署命令

示例：

```bash
curl -fsSL "https://your-cloud.example.com/api/edge/install.sh?enrollment_token=<ONE_TIME_TOKEN>" | bash
```

注册成功后，会在边缘端本地生成状态文件：

```text
$HOME/.autosec-edge/edge-state.json
```

其中包含：

- `agent_id`
- `edge_token`
- `site_name`

#### 5. 启动心跳与任务轮询

```bash
$HOME/.autosec-edge/autosec-edge --edge-api https://your-cloud.example.com --daemon
```

如需仅测试一次，可执行：

```bash
$HOME/.autosec-edge/autosec-edge --edge-api https://your-cloud.example.com
```

#### 6. 在前端验证

进入 `Edge Control` 页面后，正常情况下可以看到：

- “已注册边缘节点”表格中出现该节点
- “指定边缘节点”下拉框中出现该节点
- 点击“推荐节点”后出现能力匹配结果

---

## 🧭 部署提示

### 1. `cloud` 与 `edge` 的执行边界

- `cloud` 执行只适合云端主机本身可达的目标
- 对客户私网、实验网、台架网、OBD 工位网目标，建议默认使用 `edge`
- 当前 `sync edge task` 已调整为等待真实 edge 节点完成，而不是在云端本地伪执行

### 2. Edge 硬件能力识别

当前 edge 能力识别会综合使用：

- 系统工具探测：`lsusb`、`ip`、`iw`、`bluetoothctl`、`hciconfig`
- 设备文件探测：`/dev/pcan*`、`/proc/pcan`、`ttyUSB*`
- `python-can` 可用配置探测：PCAN / SocketCAN / slcan

这已经足够用于调度匹配，但不能替代现场环境验收。

### 3. 源码保护说明

当前 edge 方案的目标是：

- 不下发整套仓库源码
- 不要求边缘用户接触服务端环境变量
- 尽量只下发必要运行时和必要任务代码

它不是强 DRM / 强保密方案。  
如果未来商业模式强依赖 PoC 源码保护，建议进一步引入：

- native plugin / 编译型执行模块
- 远程能力网关
- opcode / 指令级任务下发，而非源码下发
- 签名校验与远程证明

---

## 🔌 常用 API

### 基础接口

- `GET /api/health`
- `GET /api/list_pocs`
- `GET /api/poc-registry`
- `POST /api/fingerprint`
- `POST /api/run_poc`
- `POST /api/run_poc_stream`
- `POST /api/execute`

### 评估接口

- `POST /api/report/generate`
- `POST /api/attack-graph/generate`
- `POST /api/physical-impact/assess`
- `POST /api/remediation/simulate`
- `POST /api/report/structured`

### 历史与证据接口

- `POST /api/save_session`
- `GET /api/history`
- `DELETE /api/history/<id>`
- `POST /api/history/delete-batch`
- `GET /api/session-artifacts/<session_id>`
- `GET /api/supervisor-metrics`

### Agent 与上下文接口

- `POST /api/topology`
- `POST /api/adaptive-context`
- `POST /api/agent-scan`

### Edge 接口

- `POST /api/edge/register`
- `POST /api/edge/heartbeat`
- `GET /api/edge/agents`
- `POST /api/edge/enrollment-tokens`
- `GET /api/edge/enrollment-tokens`
- `DELETE /api/edge/enrollment-tokens/<id>`
- `GET /api/edge/install.sh`
- `GET /api/edge/runtime/download`
- `POST /api/edge/recommendations`
- `GET /api/edge/tasks`
- `POST /api/edge/tasks`
- `GET /api/edge/tasks/next`
- `POST /api/edge/tasks/<task_id>/result`

---

## 🗂️ 项目目录结构

```text
.
├── client/
│   ├── components/
│   ├── services/
│   ├── constants.ts
│   └── vite.config.ts
├── server/
│   ├── server.py
│   ├── config.py
│   ├── poc_worker.py
│   ├── sandbox_runner.py
│   ├── edge_agent.py
│   ├── edge_capability_probe.py
│   ├── edge_requirements.py
│   ├── edge_deployment.py
│   ├── edge_task_payload.py
│   ├── poc_catalog.py
│   ├── build_nuitka.py
│   ├── build_edge_runtime.py
│   ├── mcp_server.py
│   ├── benchmarks/
│   └── pocs/
├── build/
│   └── edge_runtime/
├── assets/
└── README.md
```

说明：

- `server/server.py` 仍是当前主 API 入口
- 本次已把 PoC 路径解析、edge 能力判断、edge runtime 分发路径等公共逻辑拆分为独立模块
- 后续如果继续产品化，建议再进一步拆出 `api/`、`services/`、`models/`、`runtime/`

---

## ❓ 常见问题

### 1. 后端健康检查正常，但 Edge 注册返回 404

说明当前 `5002` 端口上的 Flask 进程并不是包含 edge 路由的最新后端进程。  
建议停止已有进程后，重新使用当前项目目录中的：

```bash
python3 server/server.py
```

### 2. 云端为什么扫不到客户局域网 IP

因为云端并不天然位于客户内网。  
如果目标位于实验网、车间网、台架网或其他私网段，请使用 edge。

### 3. Edge Control 页面里没有可选节点

请检查：

- 是否成功执行过部署命令或 `autosec-edge --register`
- `$HOME/.autosec-edge/edge-state.json` 是否已生成
- `$HOME/.autosec-edge/autosec-edge --edge-api http://localhost:5002 --daemon` 是否正在运行
- 边缘节点能力是否满足目标 PoC 的 `required_capabilities`

### 4. Agent Scan 不可用

请确认：

- 已启动 `server/mcp_server.py`
- 当前用户已在 `Profile Settings` 配置 `base_url`、`api_key` 和模型名
- 模型接口网络连通正常

### 5. 某些 PoC 无法直接运行

部分 PoC 依赖：

- 特定网络接口
- 蓝牙设备
- CAN 适配器
- Wi-Fi Monitor 模式
- SDR 工具
- 目标环境权限

这类 PoC 更适合在具备本地硬件能力的边缘节点上执行。

### 6. Edge 是否能绝对保护源码

不能。当前方案只能降低暴露面，不能提供绝对保证。

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

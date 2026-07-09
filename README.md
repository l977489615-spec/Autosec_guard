<div align="center">

# 🛡️ 智驭安盾
### SmartDrive Shield Edge · 智能网联汽车边缘端漏洞验证工作站

<p>
  <img src="https://img.shields.io/badge/Product-Edge%20Workstation-16c47f?style=flat-square" />
  <img src="https://img.shields.io/badge/PoC-317-f59e0b?style=flat-square" />
  <img src="https://img.shields.io/badge/Attack%20Surfaces-6-2563eb?style=flat-square" />
  <img src="https://img.shields.io/badge/UI-React%20%2B%20Vite-0ea5e9?style=flat-square" />
  <img src="https://img.shields.io/badge/API-Flask-64748b?style=flat-square" />
  <img src="https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-6b7280?style=flat-square" />
</p>

**智驭安盾（SmartDrive Shield Edge）** 是一款运行在测试人员本机、实验室工控机或车端测试工作站上的智能网联汽车（ICV）漏洞验证产品。在 **本机安装、本机连接车辆/台架、本机执行 PoC、本机沉淀证据、本机生成报告** 的边缘端安全验证工作站。

</div>

---

## ✨ Why Edge Workstation

智能网联汽车漏洞验证天然依赖现场资源：

- CAN / PCAN / SocketCAN 适配器
- 本地蓝牙控制器
- 支持 Monitor / Injection 的 Wi-Fi 网卡
- SDR / HackRF / RTL-SDR
- USB / USB Gadget / 车机物理接口
- 车载以太网、实验室私有网和隔离台架网络

因此，本项目现在按 **边缘端产品** 组织：

- 🧪 **本机执行 317 个 PoC**，不依赖远端节点调度
- 🔌 **本机硬件能力检测**，展示 USB、CAN、PCAN、蓝牙、Wi-Fi、SDR 状态
- 🛡️ **高风险 PoC 审批与后端强校验**（破坏性操作须审批 token，一次性使用）
- 🧱 **本机沙箱 Runner**，限制 CPU、内存、输出大小、文件句柄和访问目标
- 📊 **本地历史记录、证据、攻击图、物理影响和报告**
- 🤖 **可选多 Agent Scan / MCP**，支持任意 OpenAI 兼容 LLM，仍在本机服务内运行
- 👤 **本地用户体系、Bootstrap 管理员初始化与用户级 AI 配置**
- 🔐 **运行时安全加固**：目标范围校验、AI Key 加密存储、PDF 导出 XSS 防护、可选强制 JWT

---

## 🚀 Quick Start

### 1) 准备环境

推荐环境：

- Python `3.10+`
- Node.js `18+`
- npm `9+`
- Linux / macOS / Windows
- 硬件类 PoC 推荐 Linux：SocketCAN、BlueZ、Wi-Fi Monitor、SDR、USB 权限更完整

复制配置：

```bash
cp .env.example .env
```

### 2) 启动本机检测引擎

```bash
cd server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 server.py
```

默认地址：

- Local Engine: `http://127.0.0.1:5002`
- Health Check: `http://127.0.0.1:5002/api/health`
- Local Capability: `http://127.0.0.1:5002/api/local/capabilities`
- SQLite: `server/autosec.db`
- Log: `server/logs/autosec.log`（20MB × 5 轮转）

启动时会自动执行 Alembic 数据库迁移（`flask-migrate`）。

### 3) 启动前端

```bash
cd client
npm install
npm run dev
```

打开：

- Frontend: `http://localhost:3000`

### 4) 可选：启用 Agent Scan

```bash
cd server
source .venv/bin/activate
python3 mcp_server.py
```

Agent Scan 仍然是本机产品的一部分，只是需要额外启动本机 MCP Server：

- MCP Server: `http://127.0.0.1:5003`

在 `Profile` 页面配置任意 **OpenAI 兼容 API**（Base URL + Report / Fast / Strong 模型名 + API Key）。

---

## 🧭 First Run

1. 首次打开登录页：空库时进入 **系统初始化**（`AUTOSEC_BOOTSTRAP_MODE=edge`），创建首管理员；企业部署可设 `cli_only` 并通过 `flask create-admin` 初始化。
2. 登录后进入 `Profile`，配置 OpenAI 兼容 LLM（API Key 加密存服务端，前端不回传明文）。
3. 进入 `Local Runtime`，点击“刷新本机能力”。
4. 检查 USB、CAN、PCAN、蓝牙、Wi-Fi、SDR 是否被识别。
5. 进入 `Scan Engine`，填写目标 IP、蓝牙 MAC、CAN Interface、Wi-Fi Interface 或 RF Frequency。
6. 执行 Manual Scan / Global Scan / Agent Scan。
7. 高风险 / 破坏性 PoC 会弹出确认，须审批 token 放行，不会默认静默执行。
8. 扫描完成后进入 `Scan History` 查看证据、报告和结构化结果。

---

## 🏗️ Architecture

当前产品按边缘端本地工作站组织：

```mermaid
flowchart TD
    U[👤 Operator] --> FE[🖥️ Local React UI]
    FE --> API[⚙️ Local Flask Engine]
    FE --> LR[🔌 Local Runtime Page]

    API --> AUTH[🔐 JWT / Bootstrap / AI Config]
    API --> CAPP[🔍 Local Capability Probe]
    API --> ORCH[🧠 Scanner / Agent Orchestrator]
    API --> AUDIT[🧾 History / Artifacts / Audit]
    API --> REPORT[📊 Assessment / Report / Attack Graph]

    CAPP --> HW[🔌 CAN / PCAN / BT / Wi-Fi / SDR / USB]

    ORCH --> WORKER[🧪 poc_worker]
    WORKER --> SANDBOX[🧱 sandbox_runner]
    SANDBOX --> POCS[📚 PoC Plugins]

    SANDBOX --> RESULT[📦 Logs / Evidence / Result]
    RESULT --> AUDIT
    RESULT --> REPORT
    REPORT --> FE
    AUDIT --> FE
```

### 核心原则

- **本机就是执行面**：所有扫描动作默认在当前工作站执行。
- **Local Runtime 只做本机能力检测**：不再作为远端 Edge 节点控制台。
- **硬件类 PoC 不再排队到远端节点**：Global Scan 和 Manual Scan 会通过本机 Runner 执行。
- **AI 与密钥本机托管**：LLM 调用走用户自持 Key，服务端 Fernet 加密存储，浏览器不持久化明文。

---

## 🔌 Local Runtime

前端 `Local Runtime` 页面调用：

- `GET /api/local/capabilities`

后端使用 `server/local_capability_probe.py` 探测本机能力，输出：

- 本机网络范围
- `lsusb`、`ip`、`iw`、`bluetoothctl`、`hciconfig`、`hackrf_info`、`rtl_test`
- `python-can` 可用配置
- USB 挂载候选
- PCAN 字符设备
- SocketCAN 接口
- Wi-Fi 接口
- 蓝牙控制器
- SDR 状态

并归一化为能力标志：

- `usb`
- `can`
- `pcan`
- `wifi`
- `bluetooth`
- `sdr`

---

## 🧩 PoC Matrix

当前内置 `317` 个可执行 PoC 插件，覆盖 6 大攻击面。插件按 `server/pocs/<category>/` 组织，通过 `meta_display_id`、`meta_profiles` 和 `validation_tier` 参与统一编排。

| Category | Count | Focus | 本机依赖 |
| --- | ---: | --- | --- |
| Reconnaissance | 8 | 主机发现、端口扫描、服务枚举 | 网络可达 |
| Network | 65 | USB ADB、有线/网络 ADB、SSH、FTP、MQTT、SOME/IP、公开 CVE 主动验证等 | 网络 / USB |
| CAN Bus | 17 | CAN、UDS、OBD、DoIP、日志重放、诊断访问 | CAN / PCAN / SocketCAN / 网络可达 |
| Wireless | 108 | Wi-Fi、Bluetooth、KRACK、FragAttacks、QNX 无线面 | Wi-Fi / Bluetooth |
| Application | 76 | 车机应用、AirPlay、CarPlay、USB、WebView、Manifest、媒体解析与组件库检查 | 网络 / USB / 人工辅助 / 静态制品 |
| Advanced | 43 | OTA、RF、GPS、TPMS、V2X、固件、内核 LPE、Android 系统加固 | SDR / RF / USB / 台架 / ADB |

分层说明：

- `ACTIVE_PROBE`：常规主动探测，默认可批量执行
- `LAB_EXP` / `AUTO_EXP`：台架级实验 harness，须显式授权
- 破坏性 PoC 须审批 token，客户端 `allow_disruptive` 不能单独绕过

新增 PoC 时，按类别放入 `server/pocs/<category>/`，然后运行：

```bash
python3 server/generate_poc_registry.py
```

前端 PoC 数据库、扫描页和实验自动选择会通过 `/api/list_pocs` 动态读取插件元数据，一般不需要再手工维护前端列表。

---

## 🛡️ Safety Model

车端 PoC 可能造成 DoS、复位、总线注入或目标异常，因此系统保留多层安全控制：

- AST 提取 PoC 元数据和破坏等级
- `is_disruptive` / `meta_destructive_level` 风险判断
- 破坏性 PoC 前端确认 + 后端二次拦截（审批 token 一次性、TTL 300s）
- 本机沙箱进程执行（`start_new_session=True`）
- CPU / 内存 / 输出 / 文件句柄限制
- 网络访问白名单默认绑定目标地址；无 `target_ip` 时拒绝出站
- `run_poc` / `fingerprint` / `agent-scan` 目标范围校验
- Weaponize Agent 生成代码仅写入 `/tmp/autosec_sandbox/`，禁止覆盖仓库 PoC
- Agent 默认 `allow_disruptive=false`；人工复核须操作员在 UI 确认，不自动伪造结论
- 并发限制：`AUTOSEC_MAX_CONCURRENT_POCS`（默认 5）
- 执行日志、错误脱敏、证据和 trace_id 结构化保存

企业部署加固清单见 [`SECURITY.md`](SECURITY.md)。

---

## 📦 Project Structure

```text
.
├── client/
│   ├── components/
│   │   ├── Dashboard.tsx
│   │   ├── Scanner.tsx
│   │   ├── ManualTestModal.tsx
│   │   ├── AgentScan.tsx
│   │   ├── LocalRuntime.tsx       # 本机能力与本机 PoC 快速验证
│   │   ├── PocDatabase.tsx
│   │   ├── ScanHistory.tsx
│   │   ├── AuthPage.tsx           # 登录 / 系统初始化
│   │   └── Profile.tsx            # 用户与 OpenAI 兼容 AI 配置
│   ├── utils/security.ts          # XSS 转义 / localStorage 脱敏
│   ├── services/api.ts
│   └── package.json
├── server/
│   ├── server.py                  # 本机 Flask 检测引擎
│   ├── config.py
│   ├── security_utils.py          # 路径穿越 / 目标范围校验
│   ├── agent_execution_policy.py  # Agent 风险分级与 scope token
│   ├── local_capability_probe.py  # 本机硬件能力探测
│   ├── poc_security.py            # PoC 安全画像
│   ├── poc_worker.py              # 本机 PoC Worker
│   ├── sandbox_runner.py          # 本机沙箱 Runner
│   ├── assessment_engine.py
│   ├── agent_orchestrator.py
│   ├── mcp_server.py
│   ├── migrations/                # Alembic 数据库迁移
│   ├── pocs/
│   └── benchmarks/
├── assets/
├── docs/
│   └── nginx-tls.conf               # 生产 TLS 反向代理参考
├── SECURITY.md
├── .env.example
└── README.md
```

---

## 🔧 Configuration

`.env.example` 当前按本地边缘端工作站配置，关键项如下：

```env
AUTOSEC_SECRET_KEY=replace_with_a_long_random_secret
AUTOSEC_DB_URI=sqlite:///server/autosec.db
AUTOSEC_API=http://localhost:5002
MCP_SERVER=http://localhost:5003
AUTOSEC_HOST=127.0.0.1
AUTOSEC_PORT=5002
AUTOSEC_DEBUG=false

# 安全强化
AUTOSEC_REQUIRE_AUTH=false
AUTOSEC_CORS_ORIGINS=
AUTOSEC_MAX_CONCURRENT_POCS=5

# Bootstrap 管理员
AUTOSEC_BOOTSTRAP_MODE=edge          # edge | cli_only
# AUTOSEC_BOOTSTRAP_TOKEN=             # 可选防抢注
# AUTOSEC_ALLOW_OPEN_REGISTRATION=false
```

说明：

- `AUTOSEC_HOST=127.0.0.1` 为默认最安全绑定；局域网共享时改为 `0.0.0.0` 并开启 `AUTOSEC_REQUIRE_AUTH=true`。
- `AUTOSEC_API` 用于本机 Agent / MCP 调用主 API。
- `MCP_SERVER` 用于本机 Agent Scan。
- 企业部署推荐 `AUTOSEC_BOOTSTRAP_MODE=cli_only` + `flask create-admin` + Nginx TLS（见 `docs/nginx-tls.conf`）。
- AI 配置在 Profile 页面填写，支持任意 OpenAI 兼容服务商。

---

## 🖥️ Packaging Direction

产品化时打包完整本机工作站：

- Flask API
- React `dist`
- 内置 PoC 注册表
- 本机能力探测
- 本机沙箱 Runner
- SQLite 数据库初始化
- 一键启动器

当前仓库已经提供边缘端工作站发行包脚本：

```bash
python3 packaging/build_edge_workstation.py
```

默认使用 `PyInstaller`，这是当前最实用的交付路径。脚本会自动完成：

- 构建 React 前端，生成 `client/dist`
- 生成 `server/generated_poc_registry.py`，把 PoC 代码嵌入发行版
- 将 Flask 本机检测引擎、沙箱 Runner、本机能力探测和必要依赖打成可执行文件
- 组装客户交付目录和 zip 压缩包

当前 macOS arm64 本机验证产物：

```text
build/edge_workstation/release/autosec-guard-edge-macos-arm64/
├── autosec-guard-edge
├── start.sh
├── .env.template
└── README_RUNTIME.md

build/edge_workstation/release/autosec-guard-edge-macos-arm64.zip
```

启动发行版：

```bash
cd build/edge_workstation/release/autosec-guard-edge-macos-arm64
cp .env.template .env
./start.sh
```

打开：

```text
http://127.0.0.1:5002
```

如需更强源码保护，可以手动启用 Nuitka：

```bash
python3 packaging/build_edge_workstation.py --backend nuitka
```

注意：Nuitka 对 Scapy / python-can 这类依赖的首次编译非常慢，更适合作为正式商业发布前的加固构建，不建议作为日常调试默认方案。

### GitHub Actions 三平台打包

仓库内新增完整工作站发行 workflow：

```text
.github/workflows/edge-workstation-release.yml
```

它会在独立 runner 上分别构建：

- `linux-x64`
- `windows-x64`
- `macos-arm64`

触发方式：

- 手动触发：GitHub Actions 页面运行 `Edge Workstation Release`
- 打 tag 自动触发：

```bash
git tag v1.0.0
git push origin v1.0.0
```

CI 会执行：

- 安装 Python / Node.js 依赖
- 构建 React 前端
- 生成嵌入式 PoC 注册表
- 打包完整边缘端工作站
- 启动发行版做 `/api/health`、`/api/list_pocs` 和首页 smoke test
- 上传三平台 zip 产物
- tag 触发时自动把 zip 上传到 GitHub Release

发布给客户时只分发 CI 产出的 zip / 安装包，不分发仓库源码。仓库保持私有即可，GitHub Release 页面不需要对客户公开。

推荐最终交付形态：

| Platform | Package | 说明 |
| --- | --- | --- |
| Linux | `.deb` / `.rpm` / AppImage / tar.gz | 最适合 CAN、BlueZ、Wi-Fi Monitor、SDR |
| Windows | `.msi` / `.exe` | 适合网络类、PCAN、部分 USB |
| macOS | `.app` / `.pkg` | 适合 UI、网络类、部分 USB；底层无线能力受限 |

---

## 🔌 API Overview

### 认证与用户

- `GET /api/auth/status`
- `POST /api/register`
- `POST /api/login`
- `GET /api/profile`
- `PUT /api/profile`
- `GET /api/admin/users`
- `POST /api/admin/users`

### 本地运行时

- `GET /api/health`
- `GET /api/local/capabilities`

### PoC 执行

- `GET /api/list_pocs`
- `GET /api/poc-registry`
- `GET /api/auto_discovery`
- `POST /api/fingerprint`
- `POST /api/run_poc`
- `POST /api/run_poc_stream`
- `POST /api/execute`
- `POST /api/poc_manual_verdict`
- `POST /api/poc_manual_verdict_batch`
- `POST /api/scan_approval_policy`

### 报告与评估

- `POST /api/report/generate`
- `POST /api/report/structured`
- `POST /api/attack-graph/generate`
- `POST /api/physical-impact/assess`
- `POST /api/remediation/simulate`

### 历史与审计

- `POST /api/save_session`
- `GET /api/history`
- `DELETE /api/history/<id>`
- `POST /api/history/delete-batch`
- `GET /api/session-artifacts/<session_id>`

### Agent Scan

- `POST /api/topology`
- `POST /api/adaptive-context`
- `POST /api/agent-scan`
- `POST /api/test-ai-config`

---

## 🧪 Development Commands

```bash
cd server
python3 server.py
```

```bash
cd client
npm run dev
npm run build
```

```bash
cd server
python3 mcp_server.py
python3 validate_benchmark_suite.py
python3 run_benchmark_suite.py --strict
```

企业首管理员 CLI 初始化：

```bash
cd server
source .venv/bin/activate
export FLASK_APP=server.py
flask create-admin --username admin
```

---

## ❓ FAQ

### 1) 产品形态是什么？

当前主产品路径是本地边缘端工作站，默认 UI 和扫描流程只依赖本机执行引擎。

### 2) 首次部署如何创建管理员？

- 默认（`AUTOSEC_BOOTSTRAP_MODE=edge`）：空库时 Web 登录页显示「系统初始化」。
- 企业模式（`cli_only`）：执行 `flask create-admin`，禁止 Web 自助创建首管理员。
- 网络暴露时建议设置 `AUTOSEC_BOOTSTRAP_TOKEN` 防抢注。

### 3) 支持哪些 AI 模型？

任意 **OpenAI 兼容 API**（OpenAI、Azure OpenAI、DeepSeek、通义千问等）。在 Profile 填写 Base URL 和 Report / Fast / Strong 模型名即可，API Key 加密存服务端。

### 4) 为什么硬件能力没识别到？

请检查本机驱动和权限。例如 Linux 下需要 SocketCAN / BlueZ / `iw` / `lsusb` / SDR 工具；Windows 需要对应 PCAN 或 USB 驱动；macOS 的底层 Wi-Fi / 蓝牙能力会受系统限制。

### 5) 硬件类 PoC 现在怎么执行？

直接由本机 `poc_worker.py` 和 `sandbox_runner.py` 执行。执行前先在 `Local Runtime` 页面确认本机能力。

### 6) Agent Scan 是否还可用？

可用。它作为本机 Agent Scan 能力保留，需要启动本机 `mcp_server.py` 并在 Profile 配置 OpenAI 兼容 LLM 参数。

---

## ⚠️ Disclaimer

本项目仅可用于：

- 经授权的智能网联汽车安全测试
- 实验室台架验证
- 教学、研究、演示与方法评估
- 合规审计前的内部验证

禁止用于未授权目标、生产车辆或任何违反法律法规的场景。<br>
高风险 PoC 即使在实验环境中也应在隔离、审批和回滚预案完备的前提下执行。

---

<div align="center">
  SmartDrive Shield Edge · Local-first ICV Security Workstation
</div>

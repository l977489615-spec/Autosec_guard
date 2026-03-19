<div align="center">

# 🛡️ 智驭安盾
### SmartDrive Shield — 智能网联汽车漏洞扫描平台

<p>
  <img src="https://img.shields.io/badge/版本-v3.0.0-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/PoC%20模块-67-green?style=flat-square" />
  <img src="https://img.shields.io/badge/攻击面类别-6-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/AI%20报告-Gemini%202.5-purple?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square" />
</p>

**智驭安盾（SmartDrive Shield）** 是一款面向智能网联车辆（ICV）的自动化安全漏洞验证平台。  
集成 **67 个真实 PoC 验证模块**，覆盖侦察信息收集、网络服务、CAN 总线、无线射频、应用系统及高级攻击等 6 大攻击维度，  
并具备**目标系统智能指纹识别**与 **AI 驱动的中文安全报告生成**能力。

</div>

---

## 📸 系统截图

### 🏠 Dashboard — 态势总览

<div align="center">
  <img src="assets/dashboard.png" width="90%" alt="Dashboard" />
</div>

> 展示漏洞覆盖统计、严重程度分布、模块分类概览及系统在线状态。

---

### 🔍 Scan Engine — 扫描引擎

<div align="center">
  <img src="assets/scan_engine.png" width="90%" alt="Scan Engine" />
</div>

> 提供 **Global Auto Scan**（全局自动扫描）和 **Manual Diagnostic**（手动诊断）两种操作模式。

---

### 📦 PoC Database — 漏洞知识库

<div align="center">
  <img src="assets/poc_database.png" width="90%" alt="PoC Database" />
</div>

> 67 个 PoC 插件全览，支持按 CVE 编号、名称搜索和分类筛选。每个漏洞均附带完整的利用脚本原型。

---

### 📋 Scan History — 扫描记录与审计

<div align="center">
  <img src="assets/scan_history.png" width="90%" alt="Scan History" />
</div>

> 记录每次扫描的详细日志，支持 AI 分析报告存储与 PDF 导出，便于安全审计与复测回溯。

---

## ✨ 核心特性

| 特性 | 描述 |
|------|------|
| 🎯 **67 个真实 PoC 模块** | 全部使用原生 Python 库（`scapy`、`socket`、`subprocess`、`python-can`）进行真实网络交互，非模拟演示 |
| 🧠 **智能目标指纹识别** | 扫描前自动探测目标操作系统（QNX / Android / Linux），跳过不适用的漏洞项 |
| 🔒 **安全的 PoC 检测模式** | 所有检测仅发送 1~3 个验证探测包，绝不导致目标系统崩溃或失能 |
| 🤖 **AI 中文安全报告** | 集成 Gemini 2.5 Flash API，自动生成中文专业安全评估报告，含风险等级、漏洞分析与修复建议 |
| 📄 **PDF 报告导出** | 支持将扫描结果与 AI 报告一键导出为 PDF 文件，便于存档与汇报 |
| 🌐 **全栈攻击面覆盖** | 涵盖侦察、网络服务、CAN 总线、无线射频、应用系统、高级攻击 6 大维度 |
| ⚙️ **灵活参数化输入** | 按需输入 IP、蓝牙 MAC、CAN 接口、Wi-Fi 接口等，仅扫描与输入参数相关的漏洞 |
| 👥 **多用户 RBAC 权限管理** | 支持管理员/普通用户角色，管理员可查看全局扫描历史及管理账户 |

---

## 🗂️ 漏洞覆盖矩阵

| 类别 | 目录 | 数量 | 模块编号 | 涵盖方向 |
|------|------|:----:|----------|----------|
| **侦察 / 信息收集** | `reconnaissance/` | 8 | 01–08 | ICMP 存活探测、TCP 端口扫描、mDNS/UPnP 服务发现、SNMP 信息泄露、蓝牙 SDP 枚举、T-Box 端口探测、HTTP 服务指纹 |
| **网络服务漏洞** | `network/` | 11 | 09–18, 66 | ADB 调试端口、SSH 弱口令/硬编码凭证、Telnet 未授权、FTP 匿名访问、MQTT 未授权、D-Bus 匿名鉴权、RTSP 日志泄露、DLNA 未授权控制、HTTPS 证书无验证、**SOME/IP 服务发现信息泄露** |
| **CAN 总线 / 诊断协议** | `canbus/` | 10 | 19–27, 67 | CAN 总线嗅探、消息注入、DoS 洪泛、重放攻击、UDS 诊断会话绕过、UDS 安全访问暴力破解、UDS 内存读取、UDS 例程控制、OBD VIN 欺骗、**UDS ECUReset 未授权（0x11）** |
| **无线通信攻击** | `wireless/` | 18 | 28–43, 63, 65 | QNX Qnet 文件读取、Wi-Fi Deauth/Evil Twin/KRACK/TI 芯片溢出/未授权控制、ConnMan DHCP 溢出、Broadcom WME 溢出、蓝牙 HFP AT 溢出/BLUFFS 密钥降级/PerfektBlue/HFP UAF/按键注入/BlueBorne/BleedingTooth、**BlueFrag L2CAP DoS（CVE-2020-0022）**、**WiFi SSID 克隆自动连接** |
| **应用系统漏洞** | `application/` | 12 | 44–53, 62, 64 | AirPlay AirBorne UAF、IVI USB SQLi、CarPlay 栈溢出、HiQnet TCP/UDP 溢出、WebView 文件外泄、文件名命令注入、USB 路径注入、IVI 开发者模式绕过、无线认证绕过、**RTSP CarPlay DoS（CVE-2023-28898）**、**UPnP AVTransport 媒体注入 DoS** |
| **高级攻击 / 固件安全** | `advanced/` | 8 | 54–61 | OTA MITM 拦截、RF 钥匙扰频重放（CVE-2022-27254）、GPS 信号欺骗、TPMS 信号欺骗、V2X BSM 幽灵车注入、固件更新 TOCTOU 竞态、QNX 无签名固件加载、USB 未签名更新包 |

**合计：67 个 PoC 模块**（含 6 个基于 2025.8 CCF 杭州大赛 WP 新增）

---

## 🏗️ 技术架构

```
┌──────────────────────────────────────────────────────────────────┐
│                        React 前端 (TypeScript + Vite)             │
│         Dashboard · Scanner · PoC Database · Scan History         │
│              Profile · UserManagement · AuthPage                  │
├────────────────────────┬─────────────────────────────────────────┤
│   Gemini AI Service    │           Flask 后端 API                 │
│   geminiService.ts     │           server.py (:5002)              │
│   (中文报告生成)         │                                         │
│                        │  /api/health        /api/list_pocs       │
│                        │  /api/run_poc       /api/execute         │
│                        │  /api/fingerprint   /api/save_session    │
│                        │  /api/history       /api/login           │
│                        │  /api/register      /api/admin/*         │
├────────────────────────┴─────────────────────────────────────────┤
│                     MySQL 扫描历史数据库                            │
├──────────────────────────────────────────────────────────────────┤
│                   Pocs/ (61 个 Python 插件)                        │
│  reconnaissance · network · canbus · wireless · application · advanced │
│       scapy · python-can · AF_BLUETOOTH · raw socket · ...        │
└──────────────────────────────────────────────────────────────────┘
```

---

## 🚀 快速开始

### 环境要求

- **Node.js** ≥ 18
- **Python** ≥ 3.8
- **MySQL** ≥ 5.7（用于扫描历史存储）
- **pip 依赖**: `flask`, `flask-cors`, `flask-sqlalchemy`, `pymysql`, `bcrypt`, `pyjwt`, `scapy`, `python-can`
- **系统工具**（可选）: `nmap`, `aircrack-ng`, `hackrf_transfer`, `bluez`

### 安装与运行

```bash
# 1. 克隆项目
git clone https://github.com/Hecker986/AutoSec_Guard.git
cd AutoSec_Guard

# 2. 安装前端依赖
cd client
npm install

# 3. 配置 Gemini API Key（用于 AI 中文报告生成）
echo "API_KEY=your_gemini_api_key_here" > .env.local

# 4. 安装后端 Python 依赖
cd ../server
pip install -r requirements.txt

# 5. 配置 MySQL 数据库（默认连接: root:1@localhost/autosec_db）
#    可在 server.py 中修改 SQLALCHEMY_DATABASE_URI

# 6. 启动后端引擎（新终端）
python3 server.py

# 7. 启动前端（新终端）
cd ../client
npm run dev
```

启动后访问 **http://localhost:3000** 即可使用。首个注册用户自动获得管理员权限。

---

## 📖 使用指南

### Global Auto Scan（全局自动扫描）

1. 进入 **扫描引擎** → 选择 **Global Auto Scan**
2. 填写目标信息（按需填写，未填参数对应漏洞将自动跳过）：
   - **IP Address**: 目标车机 IP 地址
   - **Bluetooth MAC**: 目标蓝牙 MAC 地址
   - **CAN Interface**: CAN 总线接口名称（如 `can0`）
   - **Wi-Fi Interface**: 监听网卡名称（如 `wlan0mon`）
   - **RF Frequency**: 射频频率（如 `315.00MHz`）
3. 点击 **Start Scan**，系统将自动完成：
   - 🔍 **OS 指纹识别**（探测 QNX / Android / Linux）
   - ⚡ **智能跳过**不适用的漏洞
   - 🧪 **逐项执行** PoC 验证（共 67 项）
   - 🤖 **生成 AI 中文安全报告**

### Manual Diagnostic（手动诊断）

选择特定漏洞进行单项测试，可查看完整的 PoC 脚本源码、自定义参数后独立执行，并查看实时输出日志。

### 扫描历史与报告导出

- 每次完成的扫描自动保存至数据库（含 AI 报告）
- 在 **扫描记录** 页面可查看历史、重放结果
- 支持将扫描报告 **导出为 PDF** 文件

---

## 📂 项目结构

```
AutoSec_Guard/
├── client/                      ← 前端应用 (React + TypeScript + Vite)
│   ├── components/              #   页面组件
│   │   ├── Scanner.tsx          #     扫描引擎主界面（全局扫描 + 手动诊断）
│   │   ├── Dashboard.tsx        #     数据仪表盘（统计与可视化）
│   │   ├── PocDatabase.tsx      #     漏洞知识库（搜索/筛选/查看）
│   │   ├── ScanHistory.tsx      #     扫描历史记录与 PDF 导出
│   │   ├── ManualTestModal.tsx  #     手动诊断弹窗
│   │   ├── PocDetailModal.tsx   #     PoC 详情弹窗
│   │   ├── AuthPage.tsx         #     用户认证页面（登录/注册）
│   │   ├── Profile.tsx          #     用户个人资料
│   │   ├── UserManagement.tsx   #     管理员用户管理
│   │   └── ScanLogs.tsx         #     实时扫描日志组件
│   ├── services/                #   服务层
│   │   ├── api.ts               #     后端 REST API 通信接口
│   │   └── geminiService.ts     #     Gemini AI 中文报告生成
│   ├── App.tsx                  #   主应用与路由（侧边栏导航）
│   ├── index.tsx                #   React 渲染入口
│   ├── index.html               #   HTML 模板（浏览器标题：智驭安盾）
│   ├── constants.ts             #   67 个 PoC 元数据定义
│   ├── types.ts                 #   TypeScript 类型定义
│   ├── metadata.json            #   应用元数据（中文名称与描述）
│   ├── package.json             #   前端依赖清单
│   └── vite.config.ts           #   Vite 构建配置
├── server/                      ← 后端引擎 (Python + Flask)
│   ├── server.py                #   Flask API 服务器（端口 5002）
│   ├── requirements.txt         #   Python 依赖清单
│   ├── logs/                    #   运行日志（RotatingFileHandler）
│   └── pocs/                    #   67 个 PoC Python 验证脚本
│       ├── iv_plugin_base.py    #     插件基类（IVIVulnerabilityPlugin）
│       ├── reconnaissance/      #     侦察与信息收集 (01–08)
│       ├── network/             #     网络服务漏洞 (09–18)
│       ├── canbus/              #     CAN 总线与诊断协议 (19–27)
│       ├── wireless/            #     无线通信攻击 (28–43)
│       ├── application/         #     应用系统漏洞 (44–53)
│       └── advanced/            #     高级攻击与固件安全 (54–61)
├── assets/                      ← 截图与媒体资源
├── README.md
├── .gitignore
└── LICENSE
```

---

## ⚠️ 免责声明

> **本工具仅供授权的安全研究、学术用途和漏洞验证使用。**  
> 在对任何车辆或系统进行测试前，请务必获取合法授权。  
> 未经授权的使用可能违反相关法律法规。开发者不对任何非法使用承担责任。

---

## 📜 License

本项目基于 [MIT License](LICENSE) 开源发布。

---

<div align="center">
  <sub>智驭安盾 · SmartDrive Shield · Built for ICV Security Research</sub>
</div>

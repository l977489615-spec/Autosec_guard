<div align="center">

# 🛡️ AutoSec Guard

### Intelligent Connected Vehicle (ICV) Vulnerability Scanner

<p>
  <img src="https://img.shields.io/badge/version-v2.5.0-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/PoC%20Modules-60-green?style=flat-square" />
  <img src="https://img.shields.io/badge/CVEs%20Covered-23-red?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square" />
</p>

**AutoSec Guard** 是一款面向智能网联车辆 (ICV) 的自动化安全漏洞验证平台。  
集成 **60 个真实 PoC 验证模块**，覆盖 Wi-Fi、蓝牙、CAN Bus、V2X、OTA 固件及 IVI 系统等全栈攻击面，并具备**目标系统智能指纹识别**能力。

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

> 60 个 PoC 插件全览，支持按 CVE 编号、名称搜索和分类筛选。每个漏洞均附带完整的利用脚本原型（Exploit PoC Script Prototype）。

---

### 📋 Scan History — 扫描记录与审计

<div align="center">
  <img src="assets/scan_history.png" width="90%" alt="Scan History" />
</div>

> 记录每次扫描的详细日志，便于安全审计与复测回溯。

---

## ✨ 核心特性

| 特性 | 描述 |
|------|------|
| 🎯 **60 个真实 PoC 模块** | 全部使用原生 Python 库（`scapy`、`socket`、`subprocess`）进行真实网络交互，非模拟演示 |
| 🧠 **智能目标指纹识别** | 扫描前自动探测目标操作系统（QNX / Android / Linux），跳过不适用的漏洞项 |
| 🔒 **安全的 PoC 模式** | 所有检测仅发送 1~3 个验证探测包，绝不导致目标系统崩溃或失能 |
| 📊 **AI 安全报告生成** | 集成 Gemini API，对扫描结果进行智能分析，自动生成专业安全评估报告 |
| 🌐 **全栈攻击面覆盖** | 涵盖 IVI 系统、车载网络、无线射频、传感器/V2X、OTA 固件等 6 大攻击维度 |
| ⚙️ **灵活参数化输入** | 按需输入 IP、蓝牙 MAC、CAN 接口、Wi-Fi 接口等，仅扫描与输入参数相关的漏洞 |

---

## 🗂️ 漏洞覆盖矩阵

| 类别 | 数量 | 涵盖方向 |
|------|------|----------|
| **IVI System** | 29 | 端口扫描、服务发现、ADB、Telnet、Web 漏洞、UDS 诊断、SQLi 注入等 |
| **Wireless/RF** | 19 | Wi-Fi Deauth、Evil Twin、KRACK、蓝牙 BlueBorne/BleedingTooth、GPS 欺骗等 |
| **Protocol** | 10 | HTTPS 中间人、DHCP 溢出、DNS 劫持、HiQnet 堆溢出、CAN Bus 注入等 |
| **ADAS/Sensor** | 2 | V2X BSM 幽灵车注入、毫米波雷达干扰 |
| **OS/Firmware** | 6 | QNX 无签名固件、Android OTA 绕过、USB 路径遍历、TOCTOU 竞态条件等 |

---

## 🏗️ 技术架构

```
┌─────────────────────────────────────────────────────┐
│                    React Frontend                    │
│         (Dashboard / Scanner / PoC Database)         │
│                    TypeScript + Vite                  │
├─────────────────────────────────────────────────────┤
│                                                      │
│   ┌───────────┐  ┌──────────┐  ┌──────────────────┐ │
│   │ /api/exec │  │/api/fprt │  │ /api/run_poc     │ │
│   │  ute      │  │ (OS指纹) │  │ (插件执行)        │ │
│   └─────┬─────┘  └────┬─────┘  └───────┬──────────┘ │
│         │              │                │            │
│   ┌─────▼──────────────▼────────────────▼──────────┐ │
│   │           Python Flask Backend (server.py)      │ │
│   │       subprocess.run() → 真实脚本物理执行         │ │
│   └─────────────────────┬───────────────────────────┘ │
│                         │                              │
│   ┌─────────────────────▼───────────────────────────┐ │
│   │              Pocs/ (60 个 Python 脚本)            │ │
│   │  scapy · AF_BLUETOOTH · raw socket · nmap · ...  │ │
│   └──────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

---

## 🚀 快速开始

### 环境要求

- **Node.js** ≥ 18
- **Python** ≥ 3.8
- **pip 依赖**: `flask`, `flask-cors`, `scapy`, `python-can`（按需安装）
- **系统工具**（可选）: `nmap`, `aircrack-ng`, `hackrf_transfer`, `bluez`

### 安装与运行

```bash
# 1. 克隆项目
git clone https://github.com/Hecker986/AutoSec_Guard.git
cd AutoSec_Guard

# 2. 安装前端依赖
cd client
npm install

# 3. 配置 Gemini API Key（用于 AI 报告生成）
echo "GEMINI_API_KEY=your_key_here" > .env.local

# 4. 安装后端 Python 依赖
cd ../server
pip install -r requirements.txt

# 5. 启动后端引擎（新终端）
python3 server.py

# 6. 启动前端（新终端）
cd ../client
npm run dev
```

启动后访问 **http://localhost:3000** 即可使用。

---

## 📖 使用指南

### Global Auto Scan（全局自动扫描）

1. 进入 **Scan Engine** → 选择 **Global Auto Scan**
2. 填写目标信息（按需填写，未填的参数对应漏洞将自动跳过）：
   - **IP Address**: 目标车机 IP
   - **Bluetooth MAC**: 目标蓝牙 MAC 地址
   - **CAN Interface**: CAN 总线接口（如 `can0`）
   - **Wi-Fi Interface**: 监听网卡名称（如 `wlan0mon`）
   - **RF Frequency**: 射频频率（如 `315.00MHz`）
3. 点击 **Start Scan**
4. 系统将自动完成：
   - 🔍 **OS 指纹识别**（探测 QNX/Android/Linux）
   - ⚡ **智能跳过**不适用的漏洞
   - 🧪 **逐项执行** PoC 验证
   - 📊 **生成 AI 安全报告**

### Manual Diagnostic（手动诊断）

选择特定漏洞进行单项测试，可查看完整的 PoC 脚本源码、配置目标参数后执行。

---

## 📂 项目结构

```
AutoSec_Guard/
├── client/                      ← 前端应用
│   ├── components/              #   React 组件
│   │   ├── Scanner.tsx          #     扫描引擎主界面
│   │   ├── Dashboard.tsx        #     数据仪表盘
│   │   ├── PocDatabase.tsx      #     漏洞知识库
│   │   ├── ManualTestModal.tsx  #     手动诊断弹窗
│   │   └── ...
│   ├── services/                #   API 服务层
│   │   ├── api.ts               #     后端通信接口
│   │   └── geminiService.ts     #     Gemini AI 报告生成
│   ├── App.tsx                  #   主应用入口
│   ├── index.tsx                #   渲染入口
│   ├── index.html               #   HTML 模板
│   ├── constants.ts             #   60 个 PoC 元数据定义
│   ├── types.ts                 #   TypeScript 类型定义
│   ├── package.json             #   前端依赖
│   └── vite.config.ts           #   Vite 构建配置
├── server/                      ← 后端引擎
│   ├── server.py                #   Flask API 服务器
│   ├── requirements.txt         #   Python 依赖清单
│   └── pocs/                    #   60 个 PoC Python 验证脚本
│       ├── iv_plugin_base.py    #     插件基类
│       ├── 01_ICMP_Host_Discovery.py
│       ├── 19_CAN_Bus_Sniff.py
│       ├── 29_WiFi_Deauth.py
│       ├── 42_BlueBorne_BNEP_Overflow.py
│       ├── 56_GPS_Spoofing.py
│       └── ...
├── assets/                      ← 截图和媒体资源
├── README.md
├── .gitignore
└── LICENSE
```

---

## ⚠️ 免责声明

> **本工具仅供授权的安全研究和漏洞验证使用。**  
> 在对任何车辆或系统进行测试前，请务必获取合法授权。  
> 未经授权的使用可能违反法律法规。开发者不对任何非法使用承担责任。

---

## 📜 License

本项目基于 [MIT License](LICENSE) 开源发布。

---

<div align="center">
  <sub>Built with ❤️ for ICV Security Research</sub>
</div>

# AutoSec Guard — PoC 脚本模板规范

> 版本：v1.0  
> 适用范围：`server/pocs/**/*.py`（文件名以数字开头的所有插件脚本）  
> 维护方：AutoSec Guard 研发团队

---

## 一、脚本分类

| 类型 | 适用场景 | 关键区别 |
|---|---|---|
| **Type-A：标准审计脚本** | 通过 TCP/IP/HTTP/SSH/ADB 主动探测的网络/应用/系统漏洞 | 必须包含 `VULN` + `_run_poc()` + `run_active_validation` |
| **Type-B：硬件依赖脚本** | 需要 CAN/BT/RF/WiFi NIC 等物理接口才能运行 | 必须包含 `HW_REQUIREMENTS`，无需 `_run_poc` |

## 命名规范

- 前端展示名统一为：
  - 有编号漏洞：`CVE-YYYY-NNNNN <漏洞中文/短语> Active Validation`
  - 侦查类：`<技术对象/动作> Reconnaissance`
- 后端脚本文件名统一为 ASCII 规范名：
  - 漏扫/验证类：`<序号>_<CVE或主题>_Active_Validation.py`
  - 侦查类：`<序号>_<主题>_Reconnaissance.py`
- `meta_poc_name` 必须与前端展示名一致；不要再使用 `_Audit`、`_Exposure`、`Detection` 之类混杂后缀。

---

## 二、文件结构（顺序不得打乱）

```
Section 1  Shebang + 模块级 docstring
Section 2  标准导入（stdlib → 第三方 → 本地框架 → probe_utils）
Section 3  VULN 字典                      [Type-A 必须]
Section 4  HW_REQUIREMENTS 字典           [Type-B 必须，Type-A 可选]
Section 5  辅助函数（私有，以 _ 开头）    [可选]
Section 6  _run_poc(plugin) 探针函数      [Type-A 必须]
Section 7  Plugin 类                      [所有脚本必须]
Section 8  __main__ 入口块               [所有脚本必须]
```

---

## 三、各 Section 详细规范

### Section 1 — Shebang + 模块 docstring

```python
#!/usr/bin/env python3
"""
PoC Name  : <漏洞简称>
CVE       : <CVE-YYYY-NNNNN 或 CWE-NNN>
Component : <受影响组件>
Category  : <network | application | wireless | canbus | advanced | reconnaissance>
Severity  : <Critical | High | Medium | Low>
CVSS      : <分值，如 9.8>
Type      : <Type-A | Type-B>
Description: <一句话描述漏洞>
Prerequisites: <运行前提条件>
Usage     : python3 <文件名>.py <必须参数>
"""
```

**规则：**
- Shebang 必须为 `#!/usr/bin/env python3`
- docstring 使用 `"""` 三引号，必须在 shebang 之后的第一行出现
- 所有字段不得留空，未知值填 `N/A`

---

### Section 2 — 导入顺序

```python
from __future__ import annotations

# 1. stdlib（按字母序）
import re
import subprocess
import sys
from pathlib import Path

# 2. 第三方库（可选，带 try/except ImportError 降级）
try:
    import requests
except ImportError:
    requests = None

# 3. 本地框架
from active_validation_core import run_active_validation  # Type-A 必须
from iv_plugin_base import IVIVulnerabilityPlugin

# 4. probe_utils（Type-A 必须，Type-B 可选）
try:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from probe_utils import (
        ADBProbe,
        HTTPProbe,
        detection_confidence,
        service_open,
        ssh_exec,
        tcp_banner,
        version_in_range,
    )
    _PROBE_UTILS = True
except ImportError:
    _PROBE_UTILS = False
```

**规则：**
- `from __future__ import annotations` 必须是第一个 import
- stdlib、第三方、本地框架三组之间各空一行
- 所有可能缺失的第三方依赖都要 `try/except ImportError` 降级

---

### Section 3 — VULN 字典（Type-A 必须）

```python
VULN: dict = {
    # ── 必填字段 ──────────────────────────────────────────────
    "id":               1,                          # int，注册表唯一 ID
    "cve":              "CVE-YYYY-NNNNN",           # str，CVE 或 CWE 编号
    "year":             2024,                       # int，CVE 发布年份
    "domain":           "network",                  # str，漏洞领域
    "vendor_product":   "Vendor / Product Name",    # str
    "component":        "受影响子组件",              # str
    "type":             "栈溢出/RCE",                # str，漏洞类型
    "summary":          "一句话摘要。",              # str，≤ 120 字
    "source_url":       "https://nvd.nist.gov/...", # str，主要参考链接
    "affected": [                                   # list[dict]，受影响版本
        {
            "vendor":  "Vendor",
            "product": "Product",
            "versions": [
                {"version": "1.0.0", "status": "affected",
                 "lessThan": "1.0.3", "versionType": "semver"},
            ],
        }
    ],
    # ── 推荐字段 ──────────────────────────────────────────────
    "source_description": "从 NVD/厂商公告复制的原文描述。",  # str
    "poc_status":         "有公开 PoC",               # str
    "research_value":     "对车联网安全研究的意义。",    # str
    "references":         ["https://..."],            # list[str]
    "signature_tokens":   ["CVE-...", "keyword"],     # list[str]，用于模糊匹配
}
```

**规则：**
- 所有必填字段不得缺失，缺失会导致合规检查器报错
- `"affected"` 中版本范围必须是结构化字典，不得使用纯字符串（如 `"Fixed in 1.2.3"`）
- `"id"` 必须与 `generated_poc_registry.py` 中的注册 ID 一致

---

### Section 4 — HW_REQUIREMENTS 字典（Type-B 必须）

```python
HW_REQUIREMENTS: dict = {
    "hardware":   ["设备型号（品牌/型号）", "配套线缆/天线"],  # list[str]
    "connection": "接口类型（如 SocketCAN / USB HCI / USB WiFi）",  # str
    "tools":      ["工具名 >= 版本", "工具2"],                  # list[str]
    "firmware":   "所需固件版本及来源 URL",                      # str
    "setup":      "一行快速启动命令",                           # str
}
```

**规则：**
- Type-B 脚本必须包含此字典，位于 `VULN` 之后（若有 VULN）或导入块之后
- 所有字段不得使用 `"N/A"` 占位符，至少填写真实型号或 `"任意支持 X 协议的设备"`

---

### Section 5 — 辅助函数（可选，私有）

```python
def _check_version(host: str, port: int) -> dict:
    """内部辅助：版本探测，返回 {'version': str, 'error': str}。"""
    ...
```

**规则：**
- 所有辅助函数以 `_` 开头，不暴露为公共接口
- 每个函数必须有单行 docstring 说明用途和返回类型

---

### Section 6 — `_run_poc` 探针函数（Type-A 必须）

```python
def _run_poc(plugin: "SomethingPlugin", vuln: dict | None = None) -> dict:
    """
    CVE-YYYY-NNNNN 主动探针。
    返回包含 'detection_confidence' 的结果字典。
    """
    params = plugin.params or {}
    target_ip  = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port       = int(params.get("port", 80))
    allow_dis  = bool(params.get("allow_disruptive", False))

    evidence: dict = {
        "cve":       vuln.get("cve", "") if vuln else "",
        "target":    f"{target_ip}:{port}",
        "technique": "描述探针技术",
    }

    # ── 探针逻辑（以下三路任选，按优先级） ───────────────────
    # 路径 A：行为确认（crash/exploit，需 allow_disruptive=True）
    # 路径 B：CVE 特征请求/响应匹配
    # 路径 C：版本+配置精确比较

    vulnerable: bool | None = None          # True=确认 / False=已修复 / None=不确定
    level = "D"                             # 探针能达到的检测等级

    # TODO: 实现探针逻辑 ...

    return detection_confidence(level, evidence, vulnerable=vulnerable)
```

**规则：**
- 函数签名必须为 `def _run_poc(plugin, vuln=None) -> dict:`
- 必须返回 `detection_confidence(...)` 的结果（包含 `detection_confidence` 键）
- `vulnerable` 只能是 `True / False / None`，不得使用字符串或整数
- 必须响应 `allow_disruptive` 参数，破坏性操作只在该参数为 `True` 时执行
- 所有网络操作必须有超时（默认 ≤ 10 秒），不得无限阻塞

**`detection_confidence` 等级规则：**

| 等级 | 条件 | 典型探针 |
|---|---|---|
| `"A"` | crash/exploit 效果被观测到 | 服务崩溃、反弹 shell、权限提升成功 |
| `"B"` | CVE 专属载荷发送 + 特征响应匹配 | 特定错误码、协议特征字段异常 |
| `"C"` | 精确版本号 + 必要配置均确认 | TLS/SSH/HTTP/ADB 探针获取版本后语义比较 |
| `"D"` | 仅静态清单/banner | 只读到版本字符串，无主动探针 |
| `"HW"` | 必须物理硬件接口 | CAN/BT/RF 协议层攻击 |

---

### Section 7 — Plugin 类

```python
class <Name>Plugin(IVIVulnerabilityPlugin):
    """单句描述该漏洞的检测逻辑。"""

    # ── 必填元数据 ──────────────────────────────────────────
    meta_display_id      : str  = "POC-<CATEGORY>-<NNN>"   # 如 POC-NET-021
    meta_poc_name        : str  = "漏洞简称"
    meta_cve_id          : str  = "CVE-YYYY-NNNNN"
    meta_source_url      : str  = "https://nvd.nist.gov/..."
    meta_references      : list = ["https://..."]
    meta_severity        : str  = "Critical"               # Critical/High/Medium/Low
    meta_protocol        : str  = "tcp"                    # tcp/udp/can/bt/rf/adb/ssh
    meta_target_os       : list = ["linux"]                # linux/android/qnx/all
    meta_required_params : list = ["target_ip"]
    meta_profiles        : list = ["network"]              # 见 iv_plugin_base.py
    is_disruptive        : bool = False
    meta_destructive_level: str = "Safe"                   # Safe/Restart/DataLoss/Brick

    def check_prerequisites(self) -> bool:
        """检查必要前提条件，不满足时 return False 或 raise RuntimeError。"""
        if not self.target_ip or self.target_ip == "N/A":
            self.logger.error("未指定目标 IP。")
            return False
        return True

    def exploit(self):
        """
        调用 run_active_validation 执行扫描。
        Type-B 脚本直接在此实现硬件协议操作。
        """
        # Type-A 标准写法：
        return run_active_validation(self, VULN, probe=_run_poc)

        # Type-B 写法（硬件脚本示例）：
        # self.results["vulnerable"] = <bool>
        # self.results["evidence"]   = "<描述>"
        # return self.results
```

**必填元数据字段说明：**

| 字段 | 格式 | 说明 |
|---|---|---|
| `meta_display_id` | `"POC-<CAT>-<NNN>"` | CAT 取 NET/APP/WRL/CAN/ADV/RCN |
| `meta_poc_name` | 字符串 | 与 VULN["summary"] 一致 |
| `meta_cve_id` | `"CVE-YYYY-NNNNN"` | 与 VULN["cve"] 一致 |
| `meta_severity` | 枚举 | Critical / High / Medium / Low |
| `meta_protocol` | 枚举 | tcp / udp / can / bt / rf / adb / ssh / http / tls |
| `meta_profiles` | list | recon / network / bluetooth / wifi / rf / can / application / advanced |
| `is_disruptive` | bool | 会导致服务重启/崩溃时为 True |
| `meta_destructive_level` | 枚举 | Safe / Restart / DataLoss / Brick |

---

### Section 8 — `__main__` 入口块（所有脚本必须）

```python
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=VULN.get("summary", __doc__))
    parser.add_argument("target_ip",            help="目标 IP 地址")
    parser.add_argument("--port",   default=80,  type=int, help="目标端口")
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员明确授权）")
    args = parser.parse_args()

    plugin = <Name>Plugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    result = plugin.run_verify()
    import json
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
```

**规则：**
- Type-B 脚本（CAN/BT/RF）将 `target_ip` 替换为对应硬件接口参数（如 `can_interface`、`bt_mac`）
- 输出统一使用 `json.dumps(..., ensure_ascii=False, default=str)`，不得使用 `print(result)`
- 必须支持 `--disruptive` 标志（即使脚本本身是 `is_disruptive=False`）

---

## 四、完整 Type-A 最小合规示例

```python
#!/usr/bin/env python3
"""
PoC Name  : Example CVE Stack Overflow Probe
CVE       : CVE-2025-00001
Component : ExampleApp HTTP Server
Category  : network
Severity  : High
CVSS      : 7.5
Type      : Type-A
Description: ExampleApp HTTP 服务在处理超长 URI 时存在栈溢出，可触发 DoS 或 RCE。
Prerequisites: 目标 IP 可达，TCP 8080 开放。
Usage     : python3 NNN_Example_Audit.py <target_ip> [--port 8080] [--disruptive]
"""
from __future__ import annotations

import sys
from pathlib import Path

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

try:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from probe_utils import HTTPProbe, detection_confidence, service_open
    _PROBE_UTILS = True
except ImportError:
    _PROBE_UTILS = False

VULN: dict = {
    "id":             999,
    "cve":            "CVE-2025-00001",
    "year":           2025,
    "domain":         "network",
    "vendor_product": "ExampleApp",
    "component":      "HTTP Server",
    "type":           "栈溢出/DoS",
    "summary":        "ExampleApp HTTP 服务超长 URI 栈溢出，可导致 DoS 或 RCE。",
    "source_url":     "https://nvd.nist.gov/vuln/detail/CVE-2025-00001",
    "affected": [
        {
            "vendor": "Example Corp",
            "product": "ExampleApp",
            "versions": [
                {"version": "1.0.0", "status": "affected",
                 "lessThan": "1.2.0", "versionType": "semver"},
            ],
        }
    ],
    "references":       ["https://nvd.nist.gov/vuln/detail/CVE-2025-00001"],
    "signature_tokens": ["CVE-2025-00001", "ExampleApp", "stack", "overflow"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """CVE-2025-00001：向目标发送超长 URI，检测 500 或连接中断。"""
    params      = plugin.params or {}
    target_ip   = params.get("target_ip", "127.0.0.1")
    port        = int(params.get("port", 8080))
    allow_dis   = bool(params.get("allow_disruptive", False))

    evidence = {
        "cve":       "CVE-2025-00001",
        "target":    f"{target_ip}:{port}",
        "technique": "超长 URI GET 请求 → 检测服务崩溃",
    }

    if not service_open(target_ip, port):
        evidence["error"] = "端口不可达"
        return detection_confidence("E", evidence, vulnerable=None)

    probe = HTTPProbe(target_ip, port)
    server_ver = probe.get_server_version()
    evidence["server_version"] = server_ver

    if allow_dis:
        resp = probe.get("/" + "A" * 8192)
        if resp and resp.status in (500, 503) or resp is None:
            evidence["result"] = "服务崩溃或返回 5xx"
            return detection_confidence("A", evidence, vulnerable=True)

    resp = probe.get("/" + "A" * 256)
    if resp and resp.status == 500:
        evidence["result"] = f"HTTP {resp.status}"
        return detection_confidence("B", evidence, vulnerable=True)

    evidence["result"] = "服务响应正常"
    return detection_confidence("C", evidence, vulnerable=False)


class ExampleStackOverflowPlugin(IVIVulnerabilityPlugin):
    """CVE-2025-00001 ExampleApp HTTP 栈溢出探针。"""

    meta_display_id       = "POC-NET-999"
    meta_poc_name         = "Example CVE Stack Overflow Probe"
    meta_cve_id           = "CVE-2025-00001"
    meta_source_url       = "https://nvd.nist.gov/vuln/detail/CVE-2025-00001"
    meta_references       = ["https://nvd.nist.gov/vuln/detail/CVE-2025-00001"]
    meta_severity         = "High"
    meta_protocol         = "tcp"
    meta_target_os        = ["linux"]
    meta_required_params  = ["target_ip"]
    meta_profiles         = ["network"]
    is_disruptive         = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self) -> bool:
        if not self.target_ip or self.target_ip == "N/A":
            self.logger.error("未指定目标 IP。")
            return False
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)


if __name__ == "__main__":
    import argparse, json

    parser = argparse.ArgumentParser(description=VULN["summary"])
    parser.add_argument("target_ip")
    parser.add_argument("--port",       default=8080, type=int)
    parser.add_argument("--disruptive", action="store_true")
    args = parser.parse_args()

    plugin = ExampleStackOverflowPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    result = plugin.run_verify()
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
```

---

## 五、合规检查清单（自动化）

运行 `python3 server/check_poc_compliance.py` 检查所有脚本。

| 检查项 | Type-A | Type-B | 严重性 |
|---|---|---|---|
| Shebang `#!/usr/bin/env python3` | 必须 | 必须 | ERROR |
| 模块 docstring（含 PoC Name / CVE / Category 字段）| 必须 | 必须 | ERROR |
| `from __future__ import annotations` | 必须 | 推荐 | WARNING |
| `VULN` 字典含全部必填字段 | 必须 | 可选 | ERROR |
| `HW_REQUIREMENTS` 字典 | 可选 | 必须 | ERROR |
| `_run_poc(plugin, vuln=None)` 返回 `detection_confidence` | 必须 | 不适用 | ERROR |
| Plugin 类含全部必填 `meta_*` 字段 | 必须 | 必须 | ERROR |
| `exploit()` 调用 `run_active_validation` | 必须 | 不适用 | WARNING |
| `__main__` 入口块 | 必须 | 必须 | WARNING |
| `__main__` 中 `--disruptive` 参数 | 推荐 | 推荐 | INFO |
| 所有网络操作有超时设置 | 必须 | 推荐 | WARNING |
| `vulnerable` 只取 True/False/None | 必须 | 必须 | ERROR |

---

## 六、禁止事项

1. **禁止** 在 `_run_poc` 外使用裸 `socket.connect()` 而不设置超时
2. **禁止** `vulnerable = "yes"` / `vulnerable = 1` 等非布尔值
3. **禁止** 在 `VULN["affected"]` 中使用字符串版本（如 `"Fixed in 1.2.3"`）
4. **禁止** 无 `allow_disruptive` 保护的破坏性操作
5. **禁止** `print(result)` — 输出必须用 `json.dumps`
6. **禁止** 在顶层（模块级）直接执行网络请求或启动进程
7. **禁止** 硬编码凭据或 IP 地址（使用 `params.get(...)` 读取）
8. **禁止** 在 `VULN["affected"]["versions"]` 中省略 `"versionType"` 字段

---

## 七、目录与命名约定

```
pocs/
├── advanced/          # 系统级/内核/供应链漏洞
├── application/       # 应用层（AirPlay、WebView、媒体解析等）
├── canbus/            # CAN Bus / UDS / OBD 相关（Type-B）
├── network/           # 网络服务探针
├── reconnaissance/    # 被动侦察（不发送攻击载荷）
└── wireless/          # WiFi / BT / BLE / RF（多为 Type-B）
```

文件命名：`<NNN>_<VendorOrTech>_<Component>_<TypeKeyword>_Audit.py`

- `NNN`：三位数字，在所在子目录内唯一
- `Audit` 后缀：审计型脚本（推荐）；无后缀：主动攻击型脚本

---

## 八、开发新脚本完整流程

### 第一步：确认漏洞信息

在开始写代码之前，收集以下信息（全部填入 `VULN` 字典）：

| 信息项 | 来源 |
|---|---|
| CVE 编号 | NVD / MITRE / 厂商公告 |
| 受影响版本区间 | NVD JSON / GitHub Advisory |
| 漏洞类型（栈溢出/UAF/…）| 公告描述 |
| 触发条件（端口/协议/认证状态）| PoC 复现步骤 |
| 是否需要物理硬件 | 判断 Type-A 或 Type-B |

> **关键判断**：如果漏洞必须通过 CAN/BT/RF/WiFi NIC 等物理接口触发 → **Type-B**；否则 → **Type-A**。

---

### 第二步：确定文件位置和编号

```bash
# 查看目标子目录已有的最大编号
ls server/pocs/network/ | sort -n | tail -5

# 确认文件名格式
# <NNN>_<Vendor>_<Component>_<TypeKeyword>_Audit.py
# 例：068_Tesla_MCU_Firmware_Signature_Audit.py
```

---

### 第三步：复制模板并填写

```bash
# 从规范中的完整示例复制（见第四节）
cp server/pocs/network/21_CVE_2025_32061_Active_Validation.py \
   server/pocs/network/NNN_NewVendor_Component_Audit.py
```

按照以下顺序依次填写：

```
1. Shebang + docstring（PoC Name / CVE / Category / Severity / Type / Description / Prerequisites / Usage）
2. imports（stdlib → 第三方 → active_validation_core → iv_plugin_base → probe_utils）
3. VULN 字典（id / cve / year / domain / vendor_product / component / type / summary / source_url / affected）
4. HW_REQUIREMENTS（仅 Type-B）
5. 辅助函数（_check_xxx 等，可选）
6. _run_poc(plugin, vuln=None) 探针函数
7. Plugin 类（含全部 meta_* 字段 + check_prerequisites + exploit）
8. __main__ 块
```

---

### 第四步：实现 `_run_poc` 探针逻辑

根据目标漏洞选择探针策略：

```
CVE 类型               推荐探针策略                    目标等级
─────────────────────────────────────────────────────────────
网络服务栈溢出          HTTPProbe + 超大 payload         B（允许 disruptive 时 A）
默认凭据               http_default_creds_probe          B
TLS/OpenSSL            tls_get_server_info + 版本比较    B/C
SSH/系统组件版本        ssh_exec + version_in_range       C
Android 应用漏洞        ADBProbe + 版本/配置检查         C（有设备）/ D（无设备）
CAN/BT/RF 协议         直接实现硬件协议操作             HW（Type-B）
```

**探针模板（复制后修改）：**

```python
def _run_poc(plugin, vuln=None) -> dict:
    """CVE-YYYY-NNNNN 探针：<一句话描述>。"""
    params     = plugin.params or {}
    target_ip  = params.get("target_ip", "127.0.0.1")
    port       = int(params.get("port", 80))
    allow_dis  = bool(params.get("allow_disruptive", False))

    evidence = {
        "cve":       (vuln or {}).get("cve", "CVE-YYYY-NNNNN"),
        "target":    f"{target_ip}:{port}",
        "technique": "<描述探针技术>",
    }

    # 1. 端口可达性检查（快速失败）
    if not service_open(target_ip, port):
        evidence["error"] = "端口不可达"
        return detection_confidence("E", evidence, vulnerable=None)

    # 2. CVE 特征探测（B 级）
    probe = HTTPProbe(target_ip, port)
    resp  = probe.get("/api/version")
    if resp:
        evidence["server_version"] = probe.get_server_version()
        # 语义版本比较（C 级）
        if version_in_range(evidence["server_version"], ge="1.0.0", lt="1.2.0"):
            return detection_confidence("C", evidence, vulnerable=True)

    # 3. 破坏性载荷（A 级，需授权）
    if allow_dis:
        crash_resp = probe.post("/api/upload", data=b"A" * 65536)
        if crash_resp is None:  # 服务崩溃
            evidence["result"] = "服务无响应（疑似 crash）"
            return detection_confidence("A", evidence, vulnerable=True)

    evidence["result"] = "未检测到漏洞特征"
    return detection_confidence("C", evidence, vulnerable=False)
```

---

### 第五步：本地合规检查

```bash
cd server

# 检查新脚本是否满足模板规范（零 ERROR 才能提交）
python3 check_poc_compliance.py pocs --min-severity ERROR

# 自动修复机械性问题（shebang / future import / __main__）
python3 check_poc_compliance.py pocs --fix

# 编译验证（确保无语法错误）
python3 -c "
import importlib.util, sys
from pathlib import Path
sys.path.insert(0, '.')
sys.path.insert(0, 'pocs')
py = Path('pocs/network/NNN_NewVendor_Component_Audit.py')
spec = importlib.util.spec_from_file_location(py.stem, py)
mod  = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print('编译通过')
"
```

---

### 第六步：注册脚本

将新脚本信息添加到 `server/generated_poc_registry.py`：

```python
# 在对应类别的列表中添加一条记录
{
    "id":           <NNN>,           # 与 VULN["id"] 一致
    "cve":          "CVE-YYYY-NNNNN",
    "name":         "脚本显示名称",
    "file":         "pocs/network/NNN_xxx_Audit.py",
    "category":     "network",       # 与目录一致
    "severity":     "High",
    "display_id":   "POC-NET-NNN",
},
```

---

### 第七步：本地测试运行

```bash
# 无目标的冒烟测试（验证框架集成）
python3 server/pocs/network/NNN_NewVendor_Component_Audit.py 127.0.0.1 --port 8080

# 带调试日志的测试
python3 server/scan_cli.py \
    --target 127.0.0.1 \
    --filter CVE-YYYY-NNNNN \
    --mode probe

# 审计质量分级（确认新脚本达到预期等级）
python3 server/audit_exp_readiness.py 2>&1 | grep -A5 "Detection Quality"
```

---

### 第八步：提交 checklist

提交前逐项确认：

```
[ ] check_poc_compliance.py 零 ERROR
[ ] 317 + N 个脚本全部编译通过（0 失败）
[ ] VULN["id"] 已在 generated_poc_registry.py 注册
[ ] _run_poc 达到预期检测等级（A/B/C/HW）
[ ] 破坏性操作已用 allow_disruptive 保护
[ ] __main__ 可独立运行并输出 JSON
[ ] HW_REQUIREMENTS 已填写（Type-B）
[ ] 无硬编码 IP / 凭据 / 路径
```

---

## 九、常见问题速查

### Q: 我的 `_run_poc` 应该返回什么？

必须返回 `detection_confidence(level, evidence, vulnerable=<bool|None>)` 的结果：

```python
# 确认漏洞
return detection_confidence("B", evidence, vulnerable=True)

# 确认已修复
return detection_confidence("C", evidence, vulnerable=False)

# 无法判断（目标不可达 / 信息不足）
return detection_confidence("D", evidence, vulnerable=None)
```

### Q: `vulnerable` 什么时候用 `None`？

- 端口不可达，无法探测
- 版本信息获取失败
- 目标行为模糊，既不能确认也不能排除

### Q: Type-B 脚本不需要 `_run_poc`，那怎么返回结果？

直接在 `exploit()` 中操作硬件接口，将结果写入 `self.results`：

```python
def exploit(self):
    # CAN/BT/RF 操作...
    self.results["vulnerable"] = True
    self.results["evidence"]   = "收到 ECU 响应帧 ID=0x7DF"
    return self.results
```

### Q: 如何为不同 CVE 选择合适的端口列表？

```python
# 通用端口枚举（在 _run_poc 顶部）
for try_port in [port, 8080, 8443, 443, 80, 9000]:
    if service_open(target_ip, try_port):
        port = try_port
        break
else:
    return detection_confidence("E", evidence, vulnerable=None)
```

### Q: `meta_display_id` 怎么分配？

格式 `POC-<CAT>-<NNN>`，CAT 与目录对应：

| 目录 | CAT |
|---|---|
| advanced | ADV |
| application | APP |
| canbus | CAN |
| network | NET |
| reconnaissance | RCN |
| wireless | WRL |

---

*本文档由 AutoSec Guard 研发团队维护。模板规范变更时需同步更新 `check_poc_compliance.py` 中的检查规则，并对全量脚本重新运行合规检查。*

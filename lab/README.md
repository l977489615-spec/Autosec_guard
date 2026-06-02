# 实验数据采集套件

目标：按老师要求采集 10 类实验数据，证明平台不是概念设计，而是能在复杂车端攻击面下完成自动化、可控、可复现的漏洞验证。

## 保留文件

- `experiment_config.template.json`：实验目标、PoC 执行计划、Agent 任务、人工对比数据配置模板。
- `mock_vehicle_services.py`：可控 mock 车端服务环境，用于正样本和复现实验。
- `run_experiment.py`：统一实验执行器，采集 PoC 覆盖、执行效率、漏洞检出、安全控制、Agent 编排、边缘能力等数据。
- `build_experiment_workbook.py`：生成 `实验数据统计表.xlsx`。
- `can_test_records.template.csv`：CAN 网关联动测试记录模板。
- `can_gateway_test_guide.md`：没有 CAN 分析仪时的 CAN 网关测试说明。

## 推荐实验组合

最多 5 台真实车机时，建议使用混合环境：

| 环境 | 用途 |
|---|---|
| mock 车端服务 | 正样本、可复现漏洞验证、平台效率测试 |
| 真实车机 | 误报控制、安全阻断、真实车端资源适配 |
| CAN 网关接入 | CAN 重放、UDS 探测、安全阻断记录 |

## 快速步骤

### 1. 启动 mock 环境

```bash
python3 lab/mock_vehicle_services.py
```

### 2. 启动平台后端

另开终端：

```bash
python3 server/server.py
```

确认：

```bash
curl http://127.0.0.1:5002/api/health
```

### 3. 创建实验配置

```bash
cp lab/experiment_config.template.json lab/experiment_config.json
```

修改其中真实车机 IP、端口、Agent 模型配置和 CAN 接口。

当前也支持“按条件自动选 PoC”：

- 只填写 `target_ip / can_interface / bluetooth_mac / wifi_interface`
- `run_experiment.py` 会按板块自动展开对应 PoC
- 展开结果会写入 `lab/evidence/resolved_scan_targets.json`
- 自动展开已经改为 profile 驱动：脚本可声明 `meta_profiles`，未声明时会按目录、协议和 `meta_required_params` 自动推断。

如果要启用有线 USB ADB 检测，再额外填写：

- `expected_usb_serial` 或 `usb_device_serial`

此时会自动加入 `POC-NET-001 / network/01_USB_ADB_Debug.py`。

常用 profile：

- `target_ip`：默认启用 `recon / network / unknown_service`
- `can_interface`：默认启用 `can_gateway`
- `bluetooth_mac`：默认启用 `bluetooth_recon`
- `wifi_interface`：默认启用 `wifi`
- `rf_frequency`：默认启用 `rf`
- `expected_usb_serial` 或 `usb_device_serial`：默认启用 `usb_adb`

如果某台目标需要额外板块，可以在目标的 `selector.profiles` 中加入：

```json
"selector": {
  "profiles": ["application", "advanced_network"],
  "include_unknown_probe": true,
  "allow_disruptive": false
}
```

新增 PoC 时，推荐在插件类里声明：

```python
meta_display_id = "POC-NET-016"
meta_profiles = ["network"]
```

如果不声明，实验器会自动推断；如果需要更精确的实验编排，优先显式声明。

PoC 文件编号采用“类别内独立编号”，每个类别从 `01` 开始：

- `reconnaissance/01-08`
- `network/01-15`
- `canbus/01-10`
- `wireless/01-18`
- `application/01-13`
- `advanced/01-08`

后续新增脚本时，只需要在对应类别目录下使用该类别的下一个编号，例如 `network/16_New_Check.py` 或 `wireless/19_New_Check.py`。新增或重命名后运行：

```bash
python3 server/generate_poc_registry.py
```

### 4. 填写 CAN 记录

```bash
cp lab/can_test_records.template.csv lab/can_test_records.csv
```

没有执行的危险项也要记录为 `blocked_by_safety=true`。

### 5. 执行实验

```bash
python3 lab/run_experiment.py \
  --config lab/experiment_config.json \
  --output-dir lab/evidence
```

如果你希望一个目标一个目标地跑，使用：

```bash
python3 lab/run_experiment.py \
  --config lab/experiment_config.json \
  --output-dir lab/evidence \
  --target-id MOCK-LOCAL \
  --agent-task-id AGENT-MOCK-LOCAL
```

只跑扫描、不跑 Agent：

```bash
python3 lab/run_experiment.py \
  --config lab/experiment_config.json \
  --output-dir lab/evidence \
  --target-id IVI-02 \
  --skip-agent
```

### 6. 生成 Excel

```bash
python3 lab/build_experiment_workbook.py \
  --experiment-dir lab/evidence \
  --can-records lab/can_test_records.csv \
  --output lab/实验数据统计表.xlsx
```

## 论文需要的 4 张表

生成的 Excel 已对应老师要求：

1. `表1_PoC覆盖情况`
2. `表2_扫描执行结果`
3. `表3_多Agent编排`
4. `表4_CAN网关联动`

同时还包含：

- 安全控制记录
- 边缘设备能力
- 对比实验数据
- 证据归档
- 典型案例

## 注意

没有 CAN 分析仪时，不要写“CAN 分析仪联动”。建议论文写：

> CAN 总线接口/网关联动测试。

或：

> 基于网关接入的 CAN 总线收发验证。

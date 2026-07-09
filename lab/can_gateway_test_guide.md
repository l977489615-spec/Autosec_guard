# CAN 网关联动测试说明

你没有独立 CAN 分析仪时，不要在论文中写“CAN 分析仪联动”。建议写：

> CAN 总线接口/网关联动测试。

或：

> 基于网关接入的 CAN 总线收发验证。

## 必采字段

使用：

```bash
cp lab/can_test_records.template.csv lab/can_test_records.csv
```

每条记录包含：

- `case_id`
- `test_type`: replay / fuzzing / uds_injection / error_frame / overload_frame / remote_frame_dos
- `interface`: can0 / vcan0 / PCAN_USBBUS1
- `can_id`
- `frame_type`: data / remote / error / overload
- `payload_hex`
- `send_count`
- `period_ms`
- `input_file`
- `gateway_path`
- `observed_response`
- `abnormal`
- `blocked_by_safety`
- `evidence_file`
- `notes`

## 安全建议

真实车机上只做低风险记录：

```bash
candump can0 -L > lab/evidence/can_passive.log
cansend can0 7E0#0210010000000000
```

CAN 重放、模糊测试、错误帧、过载帧、远程帧 DoS 应优先在台架或 vcan 上做。真实车辆如果未授权，记录为 `blocked_by_safety=true`，用于证明平台安全可控。

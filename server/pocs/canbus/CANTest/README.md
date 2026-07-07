# CAN 总线人工实验用例

PoC 46–52 需 **USB-CAN 分析仪 + 实车/台架**，无法自动化脚本判定。请使用同目录下 CSV 在 CAN 工具中注入。

| 编号 | 文件 | 说明 |
|------|------|------|
| 46 | `poc46_replay.csv` | 车控 CAN 消息重放 |
| 47 | `poc47_fuzz.csv` | CAN 模糊测试 |
| 48 | `poc48_UDSchk.csv` | UDS 诊断注入 |
| 49 | `poc49_errormsg_dos.csv` | 错误帧 DoS |
| 50 | `poc50_overloadmsg_dos.csv` | 过载帧 DoS |
| 51 | `poc51_priormsg_dos.csv` | 优先帧 DoS |
| 52 | `poc52_remotemsg_dos.csv` | 远程帧 DoS |

统一入口查看说明：

```bash
python3 ../../application/run_experiment.py --list --include-manual
```

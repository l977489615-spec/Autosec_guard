# 已迁移的原厂扩展 PoC 目录

`server/pocs/new` 已不再承载可执行 PoC。原 `poc*.py` 脚本已按攻击面迁移到标准目录：

- Android IVI / Manifest / WebView / 应用数据 / 原生库检查：`server/pocs/application/`
- Android 系统加固 / SELinux / ASLR / procfs / dm-verity：`server/pocs/advanced/`
- DoIP / UDS / CAN 日志检查：`server/pocs/canbus/`
- Bluetooth CVE 检查：`server/pocs/wireless/`

遗留批处理入口已迁移到：

```bash
python3 server/pocs/application/run_experiment.py --list
```

主扫描引擎会通过标准目录自动发现这些 PoC；新增 PoC 请直接放入对应分类目录，不要再放入 `new/`。

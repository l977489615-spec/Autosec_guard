# PoC 迁移与报告 Agent 审计记录

## 1. Assessment Agent

已将 `ASSESSMENT_AGENT_PROMPT` 从报告模板型提示词增强为证据驱动的安全工程判断流程。新的报告逻辑要求先判断资产、信任边界、安全属性、可利用链路、证据等级和复测性，再生成报告正文。

关键约束：

- 确认漏洞必须来自 `执行结果(JSON)` 或 `漏洞发现(JSON)`。
- 静态制品类 PoC 只能写为静态审计发现，不能描述成运行时成功利用。
- 探测类 PoC 只能证明暴露面或前置条件，不能直接升级为漏洞。
- 高风险 PoC 若被跳过、待审批或人工拒绝，必须作为未验证路径处理。
- 每个确认发现必须包含证据可信度、攻击者位置、信任边界、CVSS 参考、ISO/SAE 21434 TARA、复测与验收标准。

## 2. 迁移脚本有效性

原 `server/pocs/new/poc*.py` 已迁移到标准分类目录，`server/pocs/new` 不再承载可执行 PoC。

迁移后分类：

- `application/`：Android IVI、Manifest、WebView、本地数据、原生库、USB/安装行为相关检查。
- `advanced/`：SELinux、ASLR、Zygote、dm-verity、procfs、系统权限与内核配置检查。
- `canbus/`：CAN/UDS/DoIP 与 CAN 日志检查。
- `wireless/`：Bluetooth CVE 检查。

有效性结论：

- 脚本均可被 Python 编译，且具备 `main()` 或插件式入口。
- 当前运行器支持 standalone `main() -> bool` 和 `IVIVulnerabilityPlugin` 两种形态。
- 已修复 standalone runner 的三类问题：相对路径执行目录、`sys.exit(0)` 假阳性、`print/logging.info` 证据丢失。
- 已支持通过 JSON 参数注入静态制品与日志 fixture 环境变量，例如 `android_source_text`、`android_manifest`、`sqlite_fixture_dir`、`can_log_fixture`、`uds_log_text`。
- 已将会改变设备状态的脚本标为 `Disruptive` 并接入审批逻辑，例如安装 intent、USB 节点写入、Zygote 设置修改、SELinux/dm-verity 写测试、Bluetooth 状态修改。

仍需注意：

- 多数迁移脚本是 standalone 脚本，不是标准 `IVIVulnerabilityPlugin` 类。它们已可运行，但元数据依赖 `poc_metadata_enrich.py` 的集中映射。
- ADB/蓝牙/CAN/DoIP 类 PoC 的有效性取决于真实授权设备、接口和目标可达性；无前置条件时应返回非漏洞或受限，而不是风险命中。
- 静态 lint 类 PoC 的有效性取决于传入的源码、Manifest、SQLite、日志或 APK/so 制品；无 fixture 时不应被解读为目标安全。

## 3. 组织与编排评价

当前组织方式基本可行，但仍处于“兼容型架构”而不是“统一插件架构”：

- 优点：标准分类目录更符合用户心智；主扫描能统一发现迁移 PoC；runner 能兼容旧 standalone 脚本；高风险审批能覆盖迁移脚本。
- 风险：插件类元数据与 standalone 元数据来源不同，长期维护容易漂移；目录名、profile、required params 和执行方式之间仍需要集中映射来对齐。
- 已修复：PoC 发现规则排除了 `_experiment`、`_legacy`、`run_experiment.py` 和诊断辅助脚本，避免辅助工具污染主 PoC 列表。

建议的下一阶段架构：

1. 为所有 PoC 定义统一 manifest 字段：`kind`、`category`、`profile`、`required_params`、`evidence_type`、`execution_mode`、`destructive_level`、`safety_gate`。
2. 将 standalone 脚本逐步包一层轻量适配器，输出统一 JSON：`vulnerable`、`evidence`、`confidence`、`prerequisite_status`、`side_effects`、`remediation_hint`。
3. 把静态审计、主动探测、可验证漏洞、破坏性验证分成不同执行策略，避免 Agent 把“暴露面”和“漏洞命中”混为一谈。
4. 将高风险审批从字符串等级扩展为结构化策略，例如 `requires_approval`、`requires_lab_bench`、`writes_target_state`、`may_interrupt_service`。

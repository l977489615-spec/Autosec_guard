# 攻击图与风险评估模块实现说明

模块：`assessment_engine.py`　对外接口：`server.py`　前端：`client/components/AttackGraph.tsx`

本模块负责在漏洞验证完成后，对已确认漏洞进行攻击路径建模、网络-物理风险判级与修复仿真。
当前提供**两种攻击图**，互不影响：

| 能力 | 函数 | 接口 | 说明 |
|------|------|------|------|
| 语义展开图（每漏洞独立四元链） | `generate_attack_graph(session)` | `POST /api/attack-graph/generate` | 每个漏洞展开为 入口→漏洞→能力→物理影响 的 4 节点 3 边链；节点不跨漏洞共享 |
| 增量更新 | `incremental_update_attack_graph(existing_graph, new_findings, target_name)` | `POST /api/attack-graph/update` | 仅对新增漏洞构建节点/边/路径并入既有图后重排序，不整体重建；按漏洞标签去重、节点序号防冲突 |
| 多跳攻击图（跨漏洞杀伤链） | `generate_multihop_attack_graph(session, topology=None)` | `POST /api/attack-graph/multihop` | 语义去重节点 + 转移边，推导贯穿多个漏洞的攻击链 |
| 网络-物理判级 | `assess_physical_impact(session)` | `POST /api/physical-impact/assess` | 汇总攻击域/物理影响判定整车安全等级（critical/high/medium/low） |
| 修复仿真 | `simulate_remediation(session, graph=None)` | `POST /api/remediation/simulate` | 攻击域→加固动作映射，计算被阻断路径与修复前后评分 |
| 结构化报告 | `build_structured_report(session)` | `POST /api/report/structured` | 绑定漏洞/路径/判级/修复并保留证据回溯 |

## 一、语义展开图与多跳攻击图的区别

**语义展开图**：每个漏洞各生成独立的 entry_i / vuln_i / cap_i / impact_i，节点不共享、链间不互连。
本质是规则化语义展开，把离散漏洞可视化为可解释的单跳因果链并按风险排序，不做跨漏洞推理。

**多跳攻击图**：把入口/能力/物理影响节点按语义去重共享（`entry::{域}` / `cap::{能力}` / `impact::{影响}`，
`vuln::{i}` 唯一带证据），并依据可达性转移模型在“能力节点”与“另一攻击域入口节点”之间建立
`pivots_to` 边，从而推导出贯穿多个漏洞的攻击链，例如：

```
Wi-Fi -> wifi_open_ap -> Wireless Pivot -> ADB -> adb_root_shell -> Remote Shell -> CAN -> can_uds_dos -> Bus Access -> ECU 功能扰动
（外部无线接入 → IVI 控制 → CAN 总线 → ECU，跨 3 个漏洞的杀伤链）
```

## 二、数据结构

节点（去重后）：`{id, type, label, domain?, severity?, evidence?, capability?, impact?}`，
type ∈ {entry, vulnerability, capability, impact}。

边：`{source, target, relation, gated}`，relation ∈ {exposes, enables, leads_to, pivots_to}。
- exposes：入口→漏洞　enables：漏洞→能力　leads_to：能力→物理影响（漏洞内三条边）
- pivots_to：能力→另一攻击域入口（跨漏洞转移边，由转移模型生成）
- gated=true：该转移边通往安全网关之后的车内域且被网关阻隔，计入风险代价

路径：`{id, title, riskScore, hops, physicalImpact, reachesPhysical, gatedHops, nodes[]}`，
`nodes` 为该攻击链上依次连接的节点 id 序列（每对相邻节点对应一条真实边）。

图：`{nodes[], edges[], paths[], killChainCount, summary}`。

## 三、转移（可达性）模型与多跳推导

转移模型 `PIVOT_RULES`：能力 → 获得该能力后可横向到达的下游攻击域集合。默认值（节选）：
- `remote_shell` / `privileged_access`（IVI 立足点）→ canbus / diagnostics / sensors / firmware
- `wireless_pivot` / `adjacent_access` / `media_control` → ivi
- `bus_access` / `diagnostic_access`（车内总线终点）→ 空集

多跳路径枚举：从“外部可达入口域”（web/wireless/bluetooth/physical/telematics/media/ivi）出发做 DFS，
沿 exposes→enables→(leads_to 记为终点 / pivots_to 进入下一域) 走到物理影响节点，收集攻击链。
- 防环：DFS 维护已访问漏洞集合 + chain 内节点不重复进入（转移边集合本身可能含环，如 firmware↔ivi，必须防护）
- 限深：`max_depth` 限制单链最大漏洞跳数，防组合爆炸
- 评分：`riskScore = min(100, 最高严重度 + (hops-1)×hop_bonus - gatedHops×gated_penalty)`
- 排序键：`(reachesPhysical, riskScore, hops)` 降序；`killChainCount` = 跳数≥2 且到达物理影响的链数

网关门控：当传入 `topology.has_security_gateway=true` 且 `recommended_attack_vector="direct"` 时，
通往 `gateway_protected_domains`（canbus/diagnostics）的 pivots_to 边标记 gated 并按 gated_penalty 降分。

## 四、配置驱动（运行时可调，无需改源码）

默认值内置于 `assessment_engine.py`（如严重度评分 95/78/55/25/10、判级规则、风险下降 18/12、
转移模型、多跳评分参数），**默认零配置即开箱可用**，行为与改造前一致。

如需按车型/评估标准调整，改外置文件 `assessment_config.json` 即可（或用环境变量 `ASSESSMENT_CONFIG`
指定路径）。配置项以默认值为基础做覆盖；文件缺失或解析失败时静默回退默认，不中断评估。
可覆盖项：severity_scores、level_rules、reduction、pivot_rules、external_entry_domains、
gateway_protected_domains、physical_impacts、multihop_scoring。

## 五、前端渲染

`AttackGraph.tsx` 将图渲染为 SVG 分层节点-链路图：
- 布局：多源 BFS 分层（列=层、行=层内序号），对含环转移图安全
- 节点按类型着色（entry 青 / vulnerability 按严重度 / capability 紫 / impact 红），hover 显示证据
- 边按语义着色：实线=利用边，橙虚线=pivots_to，红虚线=网关门控，橙高亮=选中链
- 攻击链选择器：点击任一链高亮对应节点/边，显示 风险分·跳数·物理·网关数
- `AgentScan.tsx` 提供“语义展开 ↔ 多跳杀伤链”切换（默认多跳，带杀伤链数徽标）

## 六、测试记录

执行环境：server 目录下 `python3`；client 目录下 `npx tsc` / `npm run build`。

回归（语义展开图行为不变）
- 输入 3 漏洞（wifi/can/adb）→ 节点 12、边 9、路径 3，与改造前一致。

多跳推导
- 同样 3 漏洞 → 节点 12（去重）、边 12、路径 6、杀伤链 3。
- 最高链：`Wi-Fi → wifi_open_ap → adb_root_shell → can_uds_dos → ECU 功能扰动`，riskScore=100，hops=3。
- 验证跨漏洞串联：确实出现 wireless→…→canbus→ECU 的多跳链。

网关门控
- 传入 `{has_security_gateway:true, recommended_attack_vector:"direct"}` → 出现 2 条 gated 转移边，
  最高链评分由 100 降为 97（门控惩罚生效）。

防环/防爆
- 单个 canbus 漏洞（非外部入口）→ 多跳路径 0 条；含 firmware↔ivi 环的图 BFS 分层正常收敛，不死循环。

配置驱动
- 临时配置把 high 评分改为 40 → 评估实时生效，最高路径分由 high(78) 变为 medium(55)。

增量更新
- 既有 3 路径并入 1 条 critical → 4 路径、最高分 95；重复并入同名漏洞 → 仍 4 路径（去重生效）。

接口连通（Flask test_client）
- `/api/attack-graph/multihop` 已注册；无 token 访问返回 401（已接线，非 404）。

前端
- BFS 分层对含环真实图收敛，7 层，SVG 尺寸有限；最高链高亮边匹配 9/9。
- `tsc --noEmit` 退出 0；`vite build` 成功（3154 模块）。

## 七、已修复缺陷

- 多跳 DFS 记录路径时，到达 impact 节点的 `chain` 已包含该节点却又追加一次，导致 `path.nodes`
  末尾出现重复的 impact 节点对（最后一段无对应边、数据不干净）。已改为 `nodes: list(chain)`，
  现各路径相邻节点对 100% 对应真实边、无重复（端到端联调发现，单模块测试未暴露）。

## 八、与专利的对应关系

- 语义展开图 + 判级 + 修复仿真 + 增量更新 + 可配置：对应已撰写的“专利二（网络-物理攻击路径图构建与风险评估）”，代码与权利要求对齐。
- 多跳攻击图（能力转移模型 + 网关门控 + 跨漏洞杀伤链推导）：与专利一（多智能体编排）、专利二（语义展开/风险评估）均不重叠，可作为独立专利方向。

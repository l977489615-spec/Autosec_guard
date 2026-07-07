# 在线可达性启发引导的攻击面探测规划器

模块：`exploration_planner.py`　接口：`server.py` `POST /api/exploration/next-actions`
依赖：`assessment_engine.py`（可达性转移模型、多跳攻击图、配置）

## 一、定位与 SOTA 关系

现有自动化渗透/攻击图研究主要为：(a) 攻击图静态分析（MulVAL/Sheyner）；(b) MDP/POMDP +
强化学习的攻击路径规划（把侦察建模为动作，与利用联合优化）；(c) 古典规划（PDDL/最佳优先）；
(d) 工业攻击路径管理（XM Cyber 图驱动持续发现）与主动利用（Pentera 横向移动）。这些方法或
依赖强化学习/大模型（需训练、随机、不可完全复现），或面向 IT 企业网（无车-物理目标、无车内
总线、无硬件依赖面）。

本模块的差异：**面向智能网联汽车、以车辆物理影响为目标、用确定性可达性启发在线引导探测**。
它复用本系统已有的能力-车域可达性转移模型作为“到物理影响”的启发函数，把攻击面探测建模为
目标导向的最佳优先主动探测，全程确定性、可复现、可审计、可做消融，无需强化学习或大模型。

与 `generate_multihop_attack_graph`（事后建模）互补：事后版解释已发现漏洞的链；本模块在
探测过程中据部分攻击图状态选择下一步探测，形成“探测→增量更新图→再引导探测”的在线闭环，
突破事后版“被检测结果封顶”的覆盖局限。

## 二、方法

### 反向可达性启发 h*(域)

由能力级转移模型 PIVOT_RULES 推导域级可达图（域→其原生能力→下游域），对物理影响目标域
（其领域规则的物理影响属于预置物理影响集合者，如 canbus、firmware、sensors、telematics）
做反向 BFS，得到每个域到达任一物理影响目标域的最短转移跳数 h*(域)。h* 越小越接近物理影响。

### 可达前沿

当前已获能力由已确认漏洞推得；可达域 = 外部可达入口域 ∪ 已获能力经转移模型可横向到达的
下游域。可达前沿 = 可达但尚未探测的域上的候选动作。仅前沿内动作进入候选，保证探测沿可达性
扩张而非盲扫。

### 动作价值

对每个候选 PoC（经领域规则归类为攻击域与利用能力）计算：

V(a) = w_reach·ReachGain(a) + w_info·InfoGain(a) − w_cost·Cost(a) − w_risk·Risk(a)

- ReachGain：基于 h*(域) 的归一化“逼近物理影响”增益（仅当前可达时计）；
- InfoGain：可达且未探域的新颖性（驱动覆盖更多攻击面）；
- Cost：硬件/接入依赖（按 profile，如 CAN/蓝牙/SDR 接入代价高）；
- Risk：破坏等级 + 网关门控（受 SEC-GW 保护车内域的探测计入门控风险）。

取 argmax 交执行器；执行后用 `incremental_update_multihop_attack_graph` 更新图、重算前沿，
循环至前沿耗尽 / 预算用尽 / 已确认到物理影响的杀伤链。权重与代价表在 `assessment_config.json`
的 `exploration_planner` 项下可配置。

## 三、关键 API

- `compute_reach_heuristic(cfg)` → {域: h*}
- `classify_candidate(poc, cfg)` → 候选 PoC 的攻击域/利用能力
- `reachable_domains(confirmed_findings, cfg)` → 当前可达域集合
- `score_action(poc, confirmed, executed, topology, ...)` → V(a) 及可审计明细
- `next_exploration_actions(candidate_pocs, confirmed, executed, topology, top_k)` → 排序后的下一步探测动作
- REST：`POST /api/exploration/next-actions`

## 四、测试与消融记录

启发正确性
- h*(canbus)=0、h*(firmware)=0、h*(sensors)=0（目标域）；h*(ivi)=1、h*(wireless)=1、
  h*(web)=1（距物理影响 1 跳）；h*(bluetooth)=2。符合域级可达图。

前沿扩张（核心行为）
- 初始无立足点时，canbus 不在可达域；获得 IVI shell（remote_shell）后，canbus、diagnostics、
  firmware、sensors 进入可达域，can_uds_dos 的可达性增益由 0 跃升至 h*=0（直达物理影响）。

消融对比（公平基线=严重度贪心，忽略可达性；预算=2 次探测）
- 基线：第 1 探把预算浪费在尚不可达的 CAN（无立足点）→ 仅确认 1 个漏洞、0 条杀伤链、最长 1 跳。
- 本方案：第 1 探 IVI 取得立足点 → 解锁 CAN → 第 2 探 CAN 命中 → 确认 2 个漏洞、1 条到 ECU 的
  杀伤链、最长 2 跳。
- 结论：同等探测预算下，在线图引导覆盖更多攻击面并发现基线完全错失的物理杀伤链。

接口/语法
- `/api/exploration/next-actions` 已注册；无 token 访问返回 401（已接线）。
- server.py / exploration_planner.py 语法 OK；确定性、无网络、无大模型，可单测可复现。

分类缺陷修复（真机数据测试发现）
- 原 `classify_finding` 用朴素子串匹配，关键词 `can` 误命中 `scan`（如 TCP_Port_Scan 被错判为
  canbus 域），会凭空捏造 CAN/ECU 杀伤链。改为词元匹配（`match_domain_rule`+`_tokenize`，字母/
  数字边界切分），并补 DoIP→诊断域规则。修复后 TCP_Port_Scan→generic、DoIP→diagnostics；
  既有多跳用例回归不变。

Live 闭环实验（真实执行打 mock 车端服务 mock_vehicle_services.py）
- 脚本：`lab/run_guided_live.py`。闭环=规划器选 PoC → sandbox_runner 真实执行打 mock 端口 →
  观测真实 vulnerable → 并入图与可达前沿 → 再选。候选 10 个网络/侦察/诊断 PoC，预算 5 次探测。
- 结果（真实执行）：
  - 顺序探测：确认 2、杀伤链 0、最长 2 跳；
  - 严重度贪心（EDVV 式，公平基线）：确认 3、杀伤链 0、最长 3 跳，未探到诊断域；
  - 在线图引导（本方案）：确认 5、杀伤链 8、最长 3 跳，探到诊断域（DoIP→诊断访问→ECU 扰动）。
- 结论：相同真实执行与预算下，仅图引导在预算内探到诊断域并形成到物理影响的杀伤链，严重度贪心
  因 DoIP 为中危被高危项挤出预算而 0 杀伤链。确定性、可复现。

## 五、面向顶会评估的建议

- 评测指标：固定探测预算下的杀伤链召回、到达物理影响的链数、达成首条物理杀伤链所需探测次数、
  攻击面覆盖率；
- 基线：随机探测、严重度贪心（EDVV 式）、纯事后多跳建模、（可选）RL/POMDP 复现；
- 消融：去 ReachGain、去 InfoGain、去网关门控、去前沿门控各做一组；
- 环境：仿真 + Android IVI + 授权实车三类，报告独立重复与置信区间。

## 六、与专利的对应关系

本模块对应“基于可达性启发的车联网在线攻击面探测引导方法”这一独立发明方向，与专利一（多智能体
编排）、专利二（事后语义展开图与风险评估）、专利三（事后多跳攻击链构建）均不重叠：其新颖点在于
以可达性启发在探测过程中在线引导攻击面探测方向，决策依据为“到车辆物理影响的可达性图”，而非
证据缺口（专利一）或事后图建模（专利二、三）。

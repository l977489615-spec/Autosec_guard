#!/usr/bin/env python3
"""深链/陷阱链基准：验证 MCTS 前瞻规划在“需在不确定性下做预算分配、链式到达车辆物理影响”的
场景下，相对贪心方法显著提升物理影响召回；并验证从执行轨迹学习的可达性先验恢复真实结构。

环境（让 severity 贪心、确定性 h* 贪心都失手，只有 MCTS 前瞻+不确定性推理能赢）：
  外部入口 ext 可直接到达：
   - 高危干扰死路 d1/d2（severity 高、不通物理影响）——诱使 severity 贪心浪费预算；
   - 陷阱链起点 t1：离物理影响“看起来近”（h* 小），但 t1 可利用概率低（常失败）——诱使
     确定性 h* 贪心一头扎进去、反复失败；
   - 可靠链起点 a1：离物理影响“看起来远”（h* 大），但整条链可利用概率高。
  陷阱链 t1→GOAL_T（GOAL_T 物理影响，但 t1 难攻陷）；可靠链 a1→a2→GOAL（高成功率）。
  紧预算下：severity 贪心打死路，h* 贪心卡在难攻陷的 t1，MCTS rollout 发现可靠链期望收益更高 → 走 a1。
"""
from __future__ import annotations

import random
import statistics
import sys
from collections import deque
from pathlib import Path

SERVER = Path(__file__).resolve().parent.parent / "server"
sys.path.insert(0, str(SERVER))

from mcts_planner import MCTSExplorationPlanner, WorldModel       # noqa: E402
import learned_reachability as lr                                 # noqa: E402

DOMAINS = ["d1", "d2", "t1", "GOAL_T", "a1", "a2", "GOAL"]
TRUE_REACH = {
    "t1": {"GOAL_T"}, "GOAL_T": set(),
    "a1": {"a2"}, "a2": {"GOAL"}, "GOAL": set(),
    "d1": set(), "d2": set(),
}
EXTERNAL = {"d1", "d2", "t1", "a1"}   # 外部直接可达域（无虚拟入口节点）
PHYSICAL = {"GOAL", "GOAL_T"}
# 真实可利用概率：陷阱链起点 t1 很低（看似近、实则难）；可靠链高
TRUE_EXPLOIT = {"d1": 0.9, "d2": 0.9,
                "t1": 0.2, "GOAL_T": 0.9,
                "a1": 0.9, "a2": 0.9, "GOAL": 0.9}
SEVERITY = {"d1": 0.95, "d2": 0.92,
            "t1": 0.6, "GOAL_T": 0.95, "a1": 0.5, "a2": 0.5, "GOAL": 0.95}
WEIGHT = {d: (5.0 if d in PHYSICAL else 1.0) for d in DOMAINS}


def true_model():
    return WorldModel(DOMAINS, TRUE_REACH, TRUE_EXPLOIT, EXTERNAL, PHYSICAL, WEIGHT)


def _reachable(compromised, reach_edges):
    r = set(EXTERNAL)
    for c in compromised:
        r |= reach_edges.get(c, set())
    return r


def _hstar(reach_edges):
    rev = {x: [] for x in DOMAINS}
    for s, ds in reach_edges.items():
        for t in ds:
            rev[t].append(s)
    h = {x: 99 for x in DOMAINS}
    q = deque(PHYSICAL)
    for g in PHYSICAL:
        h[g] = 0
    while q:
        u = q.popleft()
        for v in rev[u]:
            if h[v] > h[u] + 1:
                h[v] = h[u] + 1
                q.append(v)
    return h


def run_episode(strategy, budget, seed, plan_model):
    rng = random.Random(seed * 131 + 7)
    compromised, probed = frozenset(), frozenset()
    h_true = _hstar(TRUE_REACH)
    for _ in range(budget):
        true_cands = sorted(_reachable(compromised, TRUE_REACH) - set(probed))
        if not true_cands:
            break
        if strategy == "severity":
            a = max(true_cands, key=lambda d: SEVERITY[d])
        elif strategy == "greedy_reach":
            a = min(true_cands, key=lambda d: h_true[d])     # 确定性贪心：最逼近物理影响
        elif strategy == "mcts":
            planner = MCTSExplorationPlanner(plan_model, n_iterations=500, seed=seed)
            a, _ = planner.next_action(compromised, probed, budget - len(probed))
            # 智能体只能尝试自己模型认为可达的动作；若该动作真实不可达 → 浪费一次探测
            if a is None:
                a = true_cands[0]
        else:
            a = rng.choice(true_cands)
        probed = frozenset(probed | {a})
        # 真实环境：仅当动作真实可达且 PoC 真实命中时才攻陷；否则该次探测作废
        if a in true_cands and rng.random() < TRUE_EXPLOIT[a]:
            compromised = frozenset(compromised | {a})
    return compromised, bool(PHYSICAL & compromised)


def synth_observations(n, seed):
    """随机策略自举：记录因果可达观测(攻陷X后新解锁的域)与探测成败观测。"""
    rng = random.Random(seed)
    reach_obs, probe_obs = [], []
    for _ in range(n):
        compromised, probed = frozenset(), frozenset()
        for _ in range(len(DOMAINS)):
            cands = sorted(_reachable(compromised, TRUE_REACH) - set(probed))
            if not cands:
                break
            a = rng.choice(cands)
            probed = frozenset(probed | {a})
            ok = rng.random() < TRUE_EXPLOIT[a]
            probe_obs.append((a, ok))
            if ok:
                before = _reachable(compromised, TRUE_REACH)
                compromised = frozenset(compromised | {a})
                after = _reachable(compromised, TRUE_REACH)
                for d in (after - before):     # 攻陷 a 后新解锁的域 = a 的可达子节点
                    reach_obs.append((a, d))
    return reach_obs, probe_obs


def main():
    budget = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    seeds = 60

    reach_obs, probe_obs = synth_observations(2000, seed=1)
    learned = lr.fit_from_transitions(reach_obs, probe_obs, DOMAINS)
    learned_model = WorldModel(DOMAINS, learned["reach_edges"], learned["exploit_prob"],
                               EXTERNAL, PHYSICAL, WEIGHT)
    print("=== 从执行轨迹学习的可达边 vs 真实（验证结构恢复） ===")
    ok = 0
    for s in DOMAINS:
        le, tr = sorted(learned["reach_edges"].get(s, set())), sorted(TRUE_REACH.get(s, set()))
        same = set(le) == set(tr)
        ok += same
        print(f"  {'✓' if same else '≈'} {s:7s} 学习={le}  真实={tr}")
    print(f"  结构恢复: {ok}/{len(DOMAINS)} 域完全一致")

    print(f"\n=== 陷阱链/深链基准（预算={budget}，{seeds}种子均值）===")
    print(f"{'策略':24s} {'攻陷域数':8s} {'到物理影响率':12s}")
    for strat, label, model in [
        ("random", "随机", true_model()),
        ("severity", "严重度贪心", true_model()),
        ("greedy_reach", "确定性可达贪心(h*)", true_model()),
        ("mcts", "MCTS前瞻(真实模型)", true_model()),
        ("mcts", "MCTS前瞻(学习模型)", learned_model),
    ]:
        nc, ph = [], []
        for s in range(seeds):
            c, p = run_episode(strat, budget, s, model)
            nc.append(len(c)); ph.append(1 if p else 0)
        print(f"{label:24s} {statistics.mean(nc):6.2f}     {statistics.mean(ph)*100:6.1f}%")


if __name__ == "__main__":
    main()

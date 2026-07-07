"""MCTS（UCT）前瞻探测规划器：在“能力-车域可达性”世界模型上做多步前瞻，选择下一步攻击面
探测动作，使固定预算下到达车辆物理影响的杀伤链召回最大化。

与贪心规划器（确定性启发 h*、贝叶斯后验）相比，MCTS 通过 selection-expansion-simulation-
backpropagation 做**多步前瞻**：它能识别“当前单步收益低、但能解锁下游物理杀伤链”的探测动作，
正是贪心方法（含贝叶斯单步后验）做不到的；因此在需要跨多个漏洞链式到达物理影响的深链场景下
提升召回。世界模型的转移概率可由手工规则给出，亦可由执行轨迹学习（见 learned_reachability），
对应 2024–2026 “学习引导规划” 的方法范式。

算法出处：UCT（Kocsis & Szepesvári, ECML 2006）、POMCP（Silver & Veness, NeurIPS 2010）、
POMDP 渗透规划（Sarraute 等, AAAI 2012）。本模块将其专门化到 ICV 能力-车域可达性与物理影响目标。
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, List, Optional, Tuple


class WorldModel:
    """探测世界模型接口：刻画可达性、可利用概率、物理影响目标与奖励。

    planner 用它做前瞻模拟（rollout）；真实执行时在真实环境中落子。模型与真实环境可不同
    （planner 用学到/估计的模型规划，在真实环境中行动），这是 POMDP/MCTS 规划的标准范式。
    """

    def __init__(self, domains: List[str], reach_edges: Dict[str, set],
                 exploit_prob: Dict[str, float], external: set,
                 physical_impacts: set, weight: Dict[str, float]):
        self.domains = list(domains)
        self.reach_edges = {k: set(v) for k, v in reach_edges.items()}
        self.exploit_prob = dict(exploit_prob)
        self.external = set(external)
        self.physical = set(physical_impacts)
        self.weight = dict(weight)

    def reachable(self, compromised: FrozenSet[str]) -> set:
        """当前可达域：外部可达 ∪ 已攻陷域可转移到达的下游域。"""
        reach = set(self.external)
        for c in compromised:
            reach |= self.reach_edges.get(c, set())
        return reach

    def candidate_actions(self, compromised: FrozenSet[str], probed: FrozenSet[str]) -> List[str]:
        return sorted((self.reachable(compromised) - set(probed)))

    def reward(self, compromised: FrozenSet[str]) -> float:
        """状态奖励：已攻陷域加权和，物理影响域权重高（鼓励链式到达物理后果）。"""
        return sum(self.weight.get(d, 1.0) for d in compromised)

    def h_star(self) -> Dict[str, int]:
        """各域沿可达图到任一物理影响域的最短跳数（反向 BFS），供 rollout 目标导向。"""
        from collections import deque
        rev: Dict[str, list] = {d: [] for d in self.domains}
        for s, ds in self.reach_edges.items():
            for t in ds:
                rev.setdefault(t, []).append(s)
        INF = len(self.domains) + 1
        h = {d: INF for d in self.domains}
        q: deque = deque()
        for g in self.physical:
            if g in h:
                h[g] = 0
                q.append(g)
        while q:
            u = q.popleft()
            for v in rev.get(u, []):
                if h[v] > h[u] + 1:
                    h[v] = h[u] + 1
                    q.append(v)
        return h


@dataclass
class _Node:
    compromised: FrozenSet[str]
    probed: FrozenSet[str]
    budget: int
    parent: Optional["_Node"] = None
    action: Optional[str] = None
    children: Dict[str, "_Node"] = field(default_factory=dict)
    untried: List[str] = field(default_factory=list)
    visits: int = 0
    value: float = 0.0


class MCTSExplorationPlanner:
    def __init__(self, model: WorldModel, n_iterations: int = 400,
                 c_uct: float = 1.4, rollout_depth: Optional[int] = None, seed: int = 0):
        self.model = model
        self.n = n_iterations
        self.c = c_uct
        self.rollout_depth = rollout_depth
        self.rng = random.Random(seed)
        self._h = model.h_star()        # 目标导向 rollout 用的可达性启发
        self.rollout_eps = 0.3          # rollout 探索率：1-eps 概率朝物理影响推进

    def _expand_actions(self, node: _Node) -> List[str]:
        return self.model.candidate_actions(node.compromised, node.probed)

    def _step(self, compromised: FrozenSet[str], probed: FrozenSet[str], action: str,
              stochastic: bool) -> FrozenSet[str]:
        """对 action（探测某域）做一次（模拟）转移：以可利用概率决定是否攻陷该域。"""
        p = self.model.exploit_prob.get(action, 0.5)
        hit = (self.rng.random() < p) if stochastic else (p >= 0.5)
        if hit:
            return frozenset(compromised | {action})
        return compromised

    def _rollout(self, compromised: FrozenSet[str], probed: FrozenSet[str], budget: int) -> float:
        """随机策略 rollout 到预算耗尽，返回终局奖励。"""
        c, pr, b = compromised, probed, budget
        while b > 0:
            acts = self.model.candidate_actions(c, pr)
            if not acts:
                break
            # 目标导向 rollout：以 1-eps 概率选最逼近物理影响（h* 最小）的动作，否则随机
            if self.rng.random() < self.rollout_eps:
                a = self.rng.choice(acts)
            else:
                a = min(acts, key=lambda d: self._h.get(d, 99))
            c = self._step(c, pr, a, stochastic=True)
            pr = frozenset(pr | {a})
            b -= 1
        return self.model.reward(c)

    def plan(self) -> Optional[str]:
        raise NotImplementedError

    def next_action(self, compromised: FrozenSet[str], probed: FrozenSet[str],
                    budget: int) -> Tuple[Optional[str], Dict[str, float]]:
        """对当前状态运行 MCTS，返回最优下一步探测域及各候选动作的均值估计（可审计）。"""
        root = _Node(compromised=compromised, probed=probed, budget=budget)
        root.untried = self._expand_actions(root)
        if not root.untried:
            return None, {}

        for _ in range(self.n):
            node = root
            # 1) Selection：沿 UCB1 下降直至可扩展或终局
            while not node.untried and node.children and node.budget > 0:
                node = max(node.children.values(),
                           key=lambda ch: ch.value / ch.visits
                           + self.c * math.sqrt(math.log(node.visits + 1) / ch.visits))
            # 2) Expansion
            if node.untried and node.budget > 0:
                a = node.untried.pop(self.rng.randrange(len(node.untried)))
                new_c = self._step(node.compromised, node.probed, a, stochastic=True)
                new_pr = frozenset(node.probed | {a})
                child = _Node(compromised=new_c, probed=new_pr, budget=node.budget - 1,
                              parent=node, action=a)
                child.untried = self.model.candidate_actions(new_c, new_pr)
                node.children[a] = child
                node = child
            # 3) Simulation
            r = self._rollout(node.compromised, node.probed, node.budget)
            # 4) Backpropagation
            while node is not None:
                node.visits += 1
                node.value += r
                node = node.parent

        stats = {a: (ch.value / ch.visits if ch.visits else 0.0)
                 for a, ch in root.children.items()}
        best = max(root.children.values(), key=lambda ch: ch.visits) if root.children else None
        return (best.action if best else None), stats

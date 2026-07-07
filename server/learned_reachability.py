"""从执行轨迹学习的可达性/可利用先验：以数据驱动的转移概率替代手工 PIVOT_RULES，消除“手工
规则 ad-hoc”的方法学软肋（2024–2026 “学习引导规划” 范式）。

输入为一批探测轨迹（每条=按时间顺序确认的攻击域序列，来自多次会话/历史实验/仿真自举）。
对每条轨迹，统计“已攻陷某域后、下一步成功攻陷某下游域”的转移计数，用拉普拉斯平滑做极大似然
估计，得到 reach_edges 与转移成功概率 exploit_prob。该统计估计可复现、可审计；更大规模时可
替换为图神经网络（如物理信息 GNN）做链接/可达性预测，本模块的接口保持不变。
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Tuple


class ReachabilityModel:
    """可增量更新的能力-车域可达性模型：维护转移计数与探测成败计数，支持新轨迹到来时
    in-place 增量更新可达关系与可利用概率，无需重拟合全部历史。对应专利权3“增量更新”。
    """

    def __init__(self, all_domains, smoothing: float = 1.0, reach_threshold: float = 0.3):
        self.all_domains = list(all_domains)
        self.smoothing = smoothing
        self.reach_threshold = reach_threshold
        self._src_dst = defaultdict(float)   # (src,dst) -> 因果可达观测计数
        self._src_tot = defaultdict(float)   # src -> 该源域出现总次数
        self._succ = defaultdict(float)      # dst -> 探测成功攻陷次数
        self._att = defaultdict(float)       # dst -> 探测尝试次数

    def update(self, reach_obs: List[Tuple[str, str]], probe_obs: List[Tuple[str, bool]]):
        """增量并入新一批因果可达观测与探测成败观测（in-place，不重拟合历史）。"""
        for src, dst in reach_obs:
            self._src_dst[(src, dst)] += 1
            self._src_tot[src] += 1
        for dst, ok in probe_obs:
            self._att[dst] += 1
            if ok:
                self._succ[dst] += 1
        return self

    def reach_edges(self) -> Dict[str, set]:
        edges = {d: set() for d in self.all_domains}
        for (src, dst), c in self._src_dst.items():
            if c / max(self._src_tot[src], 1.0) >= self.reach_threshold:
                edges.setdefault(src, set()).add(dst)
        return edges

    def exploit_prob(self) -> Dict[str, float]:
        s = self.smoothing
        return {d: ((self._succ[d] + s) / (self._att[d] + 2 * s) if self._att[d] > 0 else 0.5)
                for d in self.all_domains}

    def snapshot(self) -> Dict[str, object]:
        return {"reach_edges": self.reach_edges(), "exploit_prob": self.exploit_prob()}


def fit_from_transitions(reach_obs: List[Tuple[str, str]],
                         probe_obs: List[Tuple[str, bool]],
                         all_domains: List[str],
                         smoothing: float = 1.0,
                         reach_threshold: float = 0.3) -> Dict[str, object]:
    """从因果观测学习可达结构与可利用概率（推荐用法）。

    reach_obs：(src, dst) 表示“攻陷 src 后 dst 成为新可达域”的因果观测（探测中可直接观测：
      利用某域后再扫描，看到哪些攻击面新可达）。
    probe_obs：(dst, success) 表示对 dst 的一次探测是否成功攻陷，用于估计可利用概率。
    """
    src_dst = defaultdict(float)
    src_tot = defaultdict(float)
    for src, dst in reach_obs:
        src_dst[(src, dst)] += 1
        src_tot[src] += 1
    reach_edges: Dict[str, set] = {d: set() for d in all_domains}
    for (src, dst), c in src_dst.items():
        if c / max(src_tot[src], 1.0) >= reach_threshold:
            reach_edges.setdefault(src, set()).add(dst)

    succ = defaultdict(float)
    att = defaultdict(float)
    for dst, ok in probe_obs:
        att[dst] += 1
        if ok:
            succ[dst] += 1
    exploit_prob = {d: ((succ[d] + smoothing) / (att[d] + 2 * smoothing) if att[d] > 0 else 0.5)
                    for d in all_domains}
    return {"reach_edges": reach_edges, "exploit_prob": exploit_prob}


def fit_from_traces(traces: List[List[str]], all_domains: List[str],
                    external: set, smoothing: float = 1.0,
                    reach_threshold: float = 0.15) -> Dict[str, object]:
    """从攻陷序列轨迹学习可达性结构与转移/可利用概率。

    traces：每条为按时间顺序确认攻陷的攻击域列表（如 ['web','ivi','diagnostics']）。
    返回 {reach_edges, exploit_prob}，可直接构造 mcts_planner.WorldModel。
    """
    # 转移计数：从轨迹中“某域→其后出现的相邻下游域”
    trans_succ: Dict[Tuple[str, str], float] = defaultdict(float)
    src_total: Dict[str, float] = defaultdict(float)
    # 各域被探测后成功攻陷的次数（用于可利用概率）
    domain_succ: Dict[str, float] = defaultdict(float)
    domain_attempt: Dict[str, float] = defaultdict(float)

    for tr in traces:
        for i, dom in enumerate(tr):
            domain_attempt[dom] += 1
            domain_succ[dom] += 1  # 出现在轨迹中即视为该次探测成功攻陷
            # 仅把“紧邻前驱域→当前域”记为一次可达转移（相邻转移，避免把共现误当可达）
            if i > 0:
                prev = tr[i - 1]
                if prev != dom:
                    trans_succ[(prev, dom)] += 1
                    src_total[prev] += 1

    # 拉普拉斯平滑估计转移概率，阈值化得到 reach_edges
    reach_edges: Dict[str, set] = {d: set() for d in all_domains}
    transfer_prob: Dict[Tuple[str, str], float] = {}
    for src in all_domains:
        denom = src_total.get(src, 0.0) + smoothing * len(all_domains)
        for dst in all_domains:
            if dst == src:
                continue
            num = trans_succ.get((src, dst), 0.0) + smoothing
            p = num / denom if denom > 0 else 0.0
            transfer_prob[(src, dst)] = p
            if p >= reach_threshold:
                reach_edges[src].add(dst)

    # 可利用概率：外部域用其攻陷率，内部域同理；无数据者给中性先验
    exploit_prob: Dict[str, float] = {}
    for d in all_domains:
        att = domain_attempt.get(d, 0.0)
        if att > 0:
            exploit_prob[d] = (domain_succ[d] + smoothing) / (att + 2 * smoothing)
        else:
            exploit_prob[d] = 0.5

    return {"reach_edges": reach_edges, "exploit_prob": exploit_prob,
            "transfer_prob": transfer_prob}

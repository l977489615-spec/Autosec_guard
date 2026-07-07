"""在线可达性启发引导的攻击面探测规划器（确定性、可单测、可消融）。

设计目标（面向可复现的学术评估）：
- 把攻击面探测建模为目标导向（目标=车辆物理影响）的最佳优先主动探测；
- 用已有的能力-车域可达性转移模型（assessment_engine.PIVOT_RULES）计算“到物理影响”的
  反向可达性启发 h*(域)，引导系统优先探测“可达但未探、且最可能把攻击链延伸到 ECU/物理
  影响”的攻击面；
- 全程确定性规则推导，无强化学习、无大模型，结果可复现、可审计、可与基线对比。

与 assessment_engine.generate_multihop_attack_graph（事后建模）互补：本模块在探测过程中
依据部分攻击图状态选择下一步探测动作，形成“探测→更新图→再引导探测”的在线闭环。
"""
from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Optional, Tuple

import os

import assessment_engine as ae

# 研究/消融开关：默认 False，生产检测路径只走确定性可达性启发（文件方法）。
# 贝叶斯攻击图、MCTS 等实验性策略经深链基准评估未带来稳健增益，默认屏蔽，仅供离线消融对照。
ENABLE_RESEARCH_POLICIES = os.environ.get("ENABLE_RESEARCH_POLICIES", "").lower() in ("1", "true", "yes")


# ──────────────────────────────────────────────
# 域级可达性图：由能力级转移模型 PIVOT_RULES 推导
# ──────────────────────────────────────────────
def _domain_capabilities(cfg: Dict[str, Any]) -> Dict[str, set]:
    """每个攻击域原生具备的利用能力集合（来自领域规则表）。"""
    dc: Dict[str, set] = {}
    for _kw, rule in cfg["domain_rules"]:
        dc.setdefault(rule["domain"], set()).add(rule["capability"])
    return dc


def _domain_reach_edges(cfg: Dict[str, Any]) -> Dict[str, set]:
    """域→可达下游域：源域的某能力在转移模型中可达的目标域集合。"""
    dc = _domain_capabilities(cfg)
    pivot = cfg["pivot_rules"]
    edges: Dict[str, set] = {}
    for dom, caps in dc.items():
        downs: set = set()
        for c in caps:
            downs.update(pivot.get(c, []))
        edges[dom] = {d for d in downs if d != dom}
    return edges


def _goal_domains(cfg: Dict[str, Any]) -> set:
    """目标域：其领域规则的物理影响属于预置物理影响集合的攻击域。"""
    phys = set(cfg["physical_impacts"])
    goals: set = set()
    for _kw, rule in cfg["domain_rules"]:
        if rule["impact"] in phys:
            goals.add(rule["domain"])
    return goals


def compute_reach_heuristic(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, int]:
    """反向 BFS 预计算 h*(域)=该域沿转移图到达任一物理影响目标域的最短跳数。

    h*=0 表示该域自身即目标域；不可达目标的域取一个较大值。h* 越小，越接近物理影响。
    """
    cfg = cfg or ae.load_config()
    edges = _domain_reach_edges(cfg)
    goals = _goal_domains(cfg)
    all_domains = set(edges.keys()) | {d for ds in edges.values() for d in ds} | goals

    # 反向邻接：dst -> [src...]
    rev: Dict[str, List[str]] = {d: [] for d in all_domains}
    for src, dsts in edges.items():
        for dst in dsts:
            rev.setdefault(dst, []).append(src)

    INF = len(all_domains) + 1
    h: Dict[str, int] = {d: INF for d in all_domains}
    q: deque = deque()
    for g in goals:
        h[g] = 0
        q.append(g)
    while q:
        u = q.popleft()
        for v in rev.get(u, []):
            if h[v] > h[u] + 1:
                h[v] = h[u] + 1
                q.append(v)
    return h


# ──────────────────────────────────────────────
# 候选动作分类：把候选 PoC 映射到攻击域与利用能力
# ──────────────────────────────────────────────
def classify_candidate(poc: Dict[str, Any], cfg: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """对尚未执行的候选 PoC，依据其名称/攻击面/协议关键词归类为攻击域与利用能力。

    复用领域规则表，匹配范围扩展到候选 PoC 的可读元数据字段，得到与已确认漏洞一致的语义。
    """
    cfg = cfg or ae.load_config()
    blob = " ".join(str(poc.get(k, "")) for k in
                    ("name", "poc_name", "id", "attack_surface", "protocol", "profiles"))
    return ae.match_domain_rule(blob, cfg)


# ──────────────────────────────────────────────
# 探测状态：已获能力、已探域、外部可达域、可达前沿
# ──────────────────────────────────────────────
def obtained_capabilities(confirmed_findings: List[Dict[str, Any]],
                          cfg: Optional[Dict[str, Any]] = None) -> set:
    """由已确认漏洞推得攻击者当前已获得的利用能力集合。"""
    cfg = cfg or ae.load_config()
    caps: set = set()
    for f in confirmed_findings or []:
        if not f.get("vulnerable", True):
            continue
        caps.add(ae.classify_finding(f)["capability"])
    return caps


def reachable_domains(confirmed_findings: List[Dict[str, Any]],
                      cfg: Optional[Dict[str, Any]] = None) -> set:
    """当前可达攻击域：外部可达入口域，并入已获能力经转移模型可横向到达的下游域。"""
    cfg = cfg or ae.load_config()
    reach: set = set(cfg["external_entry_domains"])
    pivot = cfg["pivot_rules"]
    for cap in obtained_capabilities(confirmed_findings, cfg):
        reach.update(pivot.get(cap, []))
    return reach


def _probed_domains(executed_pocs: List[Dict[str, Any]], cfg: Dict[str, Any]) -> set:
    return {classify_candidate(p, cfg)["domain"] for p in executed_pocs or []}


# ──────────────────────────────────────────────
# 动作价值评分与下一步选择
# ──────────────────────────────────────────────
def _severity_value(sev: str, cfg: Dict[str, Any]) -> int:
    return int(cfg["severity_scores"].get(str(sev or "medium").lower(),
                                           cfg["severity_score_fallback"]))


def score_action(poc: Dict[str, Any],
                 confirmed_findings: List[Dict[str, Any]],
                 executed_pocs: List[Dict[str, Any]],
                 topology: Optional[Dict[str, Any]] = None,
                 heuristic: Optional[Dict[str, int]] = None,
                 cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """对单个候选 PoC 计算价值 V(a)=w1·ReachGain+w2·InfoGain-w3·Cost-w4·Risk，并给出可审计明细。"""
    cfg = cfg or ae.load_config()
    h = heuristic or compute_reach_heuristic(cfg)
    ep = cfg["exploration_planner"]
    rule = classify_candidate(poc, cfg)
    domain = rule["domain"]

    reach = reachable_domains(confirmed_findings, cfg)
    probed = _probed_domains(executed_pocs, cfg)
    hmax = (max(h.values()) if h else 1) or 1

    # 可达性增益：越接近物理影响（h* 越小）增益越高；不可达域置 0
    reachable_now = domain in reach
    hd = h.get(domain, hmax)
    reach_gain = ((hmax - hd) / hmax) if reachable_now else 0.0

    # 信息增益：可达但未探的域具有新颖性
    info_gain = 1.0 if (reachable_now and domain not in probed) else 0.0

    # 代价：硬件/接入依赖（按 profile）
    profiles = poc.get("profiles") or []
    if isinstance(profiles, str):
        profiles = [profiles]
    cost_map = ep["cost_by_profile"]
    cost = max([cost_map.get(str(p), 1) for p in profiles] + [cost_map.get(domain, 1)])
    cost_n = cost / max(cost_map.values())

    # 风险：破坏等级 + 网关门控
    risk_map = ep["risk_by_destructive_level"]
    risk = risk_map.get(str(poc.get("destructive_level", "Safe")), 1)
    gated = bool((topology or {}).get("has_security_gateway")) and \
        str((topology or {}).get("recommended_attack_vector") or "direct") == "direct" and \
        domain in set(cfg["gateway_protected_domains"])
    if gated:
        risk += 2
    risk_n = risk / (max(risk_map.values()) + 2)

    value = (ep["w_reach"] * reach_gain + ep["w_info"] * info_gain
             - ep["w_cost"] * cost_n - ep["w_risk"] * risk_n)

    return {
        "poc": poc.get("name") or poc.get("poc_name") or poc.get("id"),
        "domain": domain,
        "capability": rule["capability"],
        "value": round(value, 4),
        "reachable": reachable_now,
        "h_star": hd,
        "reach_gain": round(reach_gain, 3),
        "info_gain": info_gain,
        "cost": round(cost_n, 3),
        "risk": round(risk_n, 3),
        "gated": gated,
    }


def next_exploration_actions(candidate_pocs: List[Dict[str, Any]],
                             confirmed_findings: List[Dict[str, Any]],
                             executed_pocs: Optional[List[Dict[str, Any]]] = None,
                             topology: Optional[Dict[str, Any]] = None,
                             top_k: int = 5,
                             policy: str = "heuristic",
                             cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """对候选 PoC 集合按价值排序，返回前 top_k 个下一步探测动作及可审计评分明细。

    仅保留当前可达（外部可达或已获能力可横向到达）的候选，以保证探测沿可达性扩张而非盲扫。
    policy="heuristic" 用确定性可达性启发 h*；policy="bayesian" 用贝叶斯攻击图后验概率替代
    可达性增益项（以已确认漏洞为证据动态更新各域可利用后验），通常在固定预算下提升漏洞召回。
    """
    cfg = cfg or ae.load_config()
    # 生产检测一律采用确定性可达性启发（文件方法）。贝叶斯/MCTS 等实验性策略经基准评估未带来
    # 稳健增益，默认屏蔽；仅当显式置 ENABLE_RESEARCH_POLICIES=True 时（离线消融对照）才启用。
    if policy != "heuristic" and not ENABLE_RESEARCH_POLICIES:
        policy = "heuristic"
    h = compute_reach_heuristic(cfg)
    executed_pocs = executed_pocs or []
    scored = [score_action(p, confirmed_findings, executed_pocs, topology, h, cfg)
              for p in candidate_pocs or []]

    if policy == "bayesian":
        import bayesian_attack_graph as bag
        post = bag.domain_posteriors(candidate_pocs, confirmed_findings, topology, cfg)
        ep = cfg["exploration_planner"]
        for s in scored:
            # 用后验概率替代可达性增益项；信息增益/代价/风险项沿用
            s["posterior"] = round(post.get(s["domain"], 0.0), 4)
            s["value"] = round(ep["w_reach"] * s["posterior"] + ep["w_info"] * s["info_gain"]
                               - ep["w_cost"] * s["cost"] - ep["w_risk"] * s["risk"], 4)

    frontier = [s for s in scored if s["reachable"]]
    frontier.sort(key=lambda s: (s["value"], -s["h_star"]), reverse=True)
    return {
        "actions": frontier[:top_k],
        "frontier_size": len(frontier),
        "policy": policy,
        "reachable_domains": sorted(reachable_domains(confirmed_findings, cfg)),
        "probed_domains": sorted(_probed_domains(executed_pocs, cfg)),
    }


def run_guided_exploration(candidate_pocs: List[Dict[str, Any]],
                           execute_fn,
                           budget: int,
                           topology: Optional[Dict[str, Any]] = None,
                           reach_model=None,
                           cfg: Optional[Dict[str, Any]] = None,
                           on_step=None) -> Dict[str, Any]:
    """生产可用的在线引导闭环：规划→执行→依结果更新已确认漏洞与可达性模型→重规划，循环至预算
    耗尽、前沿为空或已达车辆物理影响。对应专利权1步骤S5/S6的在线闭环。

    execute_fn(poc) -> dict：真实执行一个 PoC，返回至少含 {"vulnerable": bool, "evidence": str}。
    reach_model：可选的 learned_reachability.ReachabilityModel，每步据探测结果增量更新（权3）。
    返回已确认漏洞、探测轨迹与是否到达物理影响。
    """
    cfg = cfg or ae.load_config()
    phys = set(cfg["physical_impacts"])
    confirmed: List[Dict[str, Any]] = []
    executed: List[Dict[str, Any]] = []
    trace: List[Dict[str, Any]] = []

    for _ in range(budget):
        remaining = [p for p in candidate_pocs
                     if (p.get("name") or p.get("poc_name")) not in
                     {(e.get("name") or e.get("poc_name")) for e in executed}]
        res = next_exploration_actions(remaining, confirmed, executed, topology,
                                       top_k=1, policy="heuristic", cfg=cfg)
        if not res["actions"]:
            break
        action = res["actions"][0]
        poc = next(p for p in remaining
                   if (p.get("name") or p.get("poc_name")) == action["poc"])
        before_reach = reachable_domains(confirmed, cfg)
        result = execute_fn(poc) or {}
        executed.append(poc)
        hit = bool(result.get("vulnerable"))
        dom = action["domain"]
        if hit:
            confirmed.append({"name": action["poc"], "severity": poc.get("severity", "Medium"),
                              "vulnerable": True, "details": (result.get("evidence") or "")[:300]})
            # 增量更新可达性模型：观测“攻陷该域后新可达的下游域”（因果可达观测）+ 探测成败
            if reach_model is not None:
                after_reach = reachable_domains(confirmed, cfg)
                reach_obs = [(dom, d) for d in (after_reach - before_reach)]
                reach_model.update(reach_obs, [(dom, True)])
        elif reach_model is not None:
            reach_model.update([], [(dom, False)])
        step = {"poc": action["poc"], "domain": dom, "hit": hit, "value": action["value"]}
        trace.append(step)
        if on_step:
            on_step(step)
        # 终止：已确认漏洞所属域中出现物理影响域（已形成到物理影响的攻击链）
        if any(ae.classify_finding(f)["impact"] in phys for f in confirmed):
            break

    reached_physical = any(ae.classify_finding(f)["impact"] in phys for f in confirmed)
    return {"confirmed": confirmed, "trace": trace,
            "reached_physical": reached_physical, "probes_used": len(executed)}

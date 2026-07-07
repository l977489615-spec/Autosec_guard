"""贝叶斯攻击图（Bayesian Attack Graph）动态推理：以已确认漏洞为证据，沿能力-车域可达性
转移关系反传，更新各攻击域“存在可利用漏洞/可被攻陷”的后验概率，用于在线探测的优先级排序。

与 exploration_planner 的确定性可达性启发（h*）相比，本模块用有理论基础的概率推理替代手工
启发：对每个攻击域设先验可利用概率（由候选 PoC 严重度推得），对可达性转移边用 noisy-OR 条件
概率（受网关门控削弱），在观测到部分漏洞后做精确因子图推理（域数较小，2^N 枚举即精确；更大
规模可改用文献中线性复杂度的 Loopy Belief Propagation）。后验越高的未探域越值得优先探测，
从而在固定预算下提升漏洞召回。

参考：Bayesian Attack Graphs 用于动态风险评估与证据传播（Poolsappasit 等 2012；Muñoz-
González 等精确/近似推理 2017）。本模块将其专门化到智能网联汽车的能力-车域可达性与网关门控。
"""
from __future__ import annotations

from itertools import product
from typing import Any, Dict, List, Optional

import assessment_engine as ae


# 严重等级到“直接可利用”先验概率
SEVERITY_PRIOR = {"critical": 0.9, "high": 0.7, "medium": 0.5, "low": 0.3, "info": 0.2, "": 0.3}


def _domain_reach_edges(cfg: Dict[str, Any]) -> Dict[str, set]:
    """域→可达下游域（与 exploration_planner 同源，由能力级转移模型推导）。"""
    dc: Dict[str, set] = {}
    for _kw, rule in cfg["domain_rules"]:
        dc.setdefault(rule["domain"], set()).add(rule["capability"])
    pivot = cfg["pivot_rules"]
    edges: Dict[str, set] = {}
    for dom, caps in dc.items():
        downs: set = set()
        for c in caps:
            downs.update(pivot.get(c, []))
        edges[dom] = {d for d in downs if d != dom}
    return edges


def build_model(candidate_pocs: List[Dict[str, Any]],
                topology: Optional[Dict[str, Any]] = None,
                cfg: Optional[Dict[str, Any]] = None,
                base_transfer: float = 0.5,
                gated_transfer: float = 0.2) -> Dict[str, Any]:
    """构建贝叶斯攻击图模型：域节点、可达性转移父子关系、先验与转移条件概率。

    - 域先验 q_D：外部可达入口域取该域候选 PoC 的最高严重度先验；内部域取较低基线（需先有立足点）。
    - 转移概率 t_{p→D}：基础值 base_transfer；若 D 为受网关保护车内域且拓扑指示网关阻隔，取 gated_transfer。
    """
    cfg = cfg or ae.load_config()
    edges = _domain_reach_edges(cfg)
    external = set(cfg["external_entry_domains"])
    gated_protected = set(cfg["gateway_protected_domains"])
    gateway_blocks = bool((topology or {}).get("has_security_gateway")) and \
        str((topology or {}).get("recommended_attack_vector") or "direct") == "direct"

    domains = sorted(set(edges.keys()) | {d for ds in edges.values() for d in ds} | external)

    # 各域候选 PoC 的最高严重度先验
    dom_sev: Dict[str, float] = {}
    for poc in candidate_pocs or []:
        dom = ae.classify_candidate(poc, cfg)["domain"] if hasattr(ae, "classify_candidate") else \
            ae.match_domain_rule(str(poc.get("name", "")), cfg)["domain"]
        s = SEVERITY_PRIOR.get(str(poc.get("severity", "")).lower(), 0.3)
        dom_sev[dom] = max(dom_sev.get(dom, 0.0), s)

    priors: Dict[str, float] = {}
    for d in domains:
        if d in external:
            priors[d] = 0.6 * dom_sev.get(d, 0.3)   # 外部域可直接尝试，先验取候选严重度折算
        else:
            priors[d] = 0.02                         # 内部域近零先验：仅经转移自父域获得概率

    # 父子：parent p -> child D（p 可转移到 D）
    parents: Dict[str, List[str]] = {d: [] for d in domains}
    transfer: Dict[tuple, float] = {}
    for p, ds in edges.items():
        for d in ds:
            parents[d].append(p)
            transfer[(p, d)] = gated_transfer if (gateway_blocks and d in gated_protected) else base_transfer

    return {"domains": domains, "parents": parents, "priors": priors,
            "transfer": transfer, "external": external}


def _node_cond_prob(d: str, state: Dict[str, int], model: Dict[str, Any]) -> float:
    """noisy-OR 条件概率 P(X_d=1 | 父节点状态)：D 直接可利用，或某已攻陷父域成功转移到 D。"""
    q = model["priors"][d]
    prod = 1.0 - q
    for p in model["parents"][d]:
        if state.get(p, 0) == 1:
            prod *= (1.0 - model["transfer"][(p, d)])
    return 1.0 - prod


def infer_marginals(model: Dict[str, Any],
                    evidence: Optional[Dict[str, int]] = None) -> Dict[str, float]:
    """精确因子图推理：枚举联合状态，返回各域 P(X_d=1 | evidence)。

    evidence：{域: 1} 表示该域已确认存在可利用漏洞（观测证据）。域数较小（≈10），2^N 枚举即精确。
    """
    evidence = evidence or {}
    domains = model["domains"]
    free = [d for d in domains if d not in evidence]
    total = 0.0
    marg = {d: 0.0 for d in domains}
    for combo in product([0, 1], repeat=len(free)):
        state = dict(evidence)
        for d, v in zip(free, combo):
            state[d] = v
        # 联合权重 = Π_d P(X_d=state_d | 父状态)
        w = 1.0
        for d in domains:
            p1 = _node_cond_prob(d, state, model)
            w *= p1 if state[d] == 1 else (1.0 - p1)
        total += w
        for d in domains:
            if state[d] == 1:
                marg[d] += w
    if total <= 0:
        return {d: 0.0 for d in domains}
    return {d: marg[d] / total for d in domains}


def domain_posteriors(candidate_pocs: List[Dict[str, Any]],
                      confirmed_findings: List[Dict[str, Any]],
                      topology: Optional[Dict[str, Any]] = None,
                      cfg: Optional[Dict[str, Any]] = None) -> Dict[str, float]:
    """便捷接口：由候选与已确认漏洞构建模型并推理，返回各域可利用后验概率。

    已确认漏洞所属域作为证据（X=1）；输出可直接用于在线探测的优先级排序。
    """
    cfg = cfg or ae.load_config()
    model = build_model(candidate_pocs, topology, cfg)
    evidence: Dict[str, int] = {}
    for f in confirmed_findings or []:
        if f.get("vulnerable", True):
            evidence[ae.classify_finding(f)["domain"]] = 1
    return infer_marginals(model, evidence)

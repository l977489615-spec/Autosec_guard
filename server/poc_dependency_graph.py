"""基于 PoC 元数据依赖图与执行结果反馈的动态攻击路径构建。

将攻击面探测从域级可达性启发（exploration_planner.py）提升到 PoC 实例级：
- 节点 = 单个 PoC 实例，状态 ∈ {pending, activated, running, success, failed, skipped}
- 边 = PoC 间的依赖/触发关系，由元数据静态推导 + 执行结果动态激活
- 在线闭环：执行 PoC → 解析输出 → 激活下游 PoC → 选择下一个 → 循环

与 VulnBot PTG（arXiv 2501.13411）思路一致：执行驱动的动态任务图，但本模块
基于 PoC 元数据（required_params, profiles, attack_surface, category）做静态
依赖推导，不依赖 LLM 做图构建，可复现、可审计。
"""
from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


class PocState(str, Enum):
    PENDING = "pending"
    ACTIVATED = "activated"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class EdgeType(str, Enum):
    PARAM_DEPENDENCY = "param_dep"
    PROFILE_CAPABILITY = "profile_cap"
    ATTACK_SURFACE_CHAIN = "surface_chain"
    CATEGORY_PROGRESSION = "category_prog"
    EXECUTION_TRIGGER = "exec_trigger"


CATEGORY_ORDER = {
    "reconnaissance": 0,
    "network": 1, "new_network": 1,
    "application": 2, "new_application": 2,
    "new_system": 2,
    "canbus": 3, "new_can": 3,
    "wireless": 3, "new_wireless": 3, "new_peripheral": 3,
    "advanced": 4, "new_advanced": 4,
}

SURFACE_ORDER = {
    "网络服务": 0,
    "车机APP/应用": 1,
    "系统配置/本地制品": 1,
    "CAN/UDS/OBD": 2,
    "无线/外设接口": 2,
    "固件/USB/OTA": 3,
    "第三方组件/高级漏洞": 3,
    "其他": 1,
}

PROFILE_GRANTS = {
    "recon": {"target_ip", "target_port", "interface"},
    "network": {"target_ip"},
    "application": {"target_ip", "target_dir"},
    "usb_adb": {"expected_usb_serial"},
    "bluetooth_recon": {"bluetooth_mac", "bd_addr"},
    "can_extended": {"can_interface"},
    "can_gateway": {"can_interface"},
}

SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}

RISK_BY_DESTRUCTIVE = {"Safe": 0.0, "Low": 0.2, "Medium": 0.5, "High": 0.8, "Critical": 1.0}


@dataclass
class PocNode:
    poc_id: str
    poc_file: str
    poc_name: str
    category: str
    severity: str
    protocol: str
    profiles: List[str]
    required_params: List[str]
    attack_surface: str
    destructive_level: str
    is_disruptive: bool
    state: PocState = PocState.PENDING
    execution_result: Optional[Dict[str, Any]] = None
    evidence_score: float = 0.0
    depth: int = 0
    activated_by: Optional[str] = None


@dataclass
class DependencyEdge:
    source: str
    target: str
    edge_type: EdgeType
    weight: float = 1.0
    condition: str = ""


@dataclass
class AttackPath:
    nodes: List[str] = field(default_factory=list)
    edges: List[Tuple[str, str]] = field(default_factory=list)
    total_severity: float = 0.0
    depth: int = 0
    success_rate: float = 0.0


class PocDependencyGraph:
    """PoC 实例级依赖图：从 poc_coverage.json 元数据构建静态依赖，执行结果动态激活。"""

    def __init__(self, available_params: Optional[Dict[str, str]] = None):
        self.nodes: Dict[str, PocNode] = {}
        self.edges: List[DependencyEdge] = []
        self._adj: Dict[str, List[DependencyEdge]] = defaultdict(list)
        self._rev: Dict[str, List[DependencyEdge]] = defaultdict(list)
        self.available_params: Dict[str, str] = dict(available_params or {})
        self.granted_params: Set[str] = set(self.available_params.keys())
        self.granted_profiles: Set[str] = set()
        self.execution_history: List[Dict[str, Any]] = []
        self.attack_paths: List[AttackPath] = []
        self._exec_order: int = 0

    def load_from_coverage(self, coverage_path: str):
        path = Path(coverage_path)
        if not path.exists():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        pocs = data.get("pocs", [])
        for entry in pocs:
            rp = entry.get("required_params", "")
            if isinstance(rp, str):
                req = [p.strip() for p in rp.split(",") if p.strip()]
            else:
                req = list(rp or [])
            profiles = entry.get("profiles", [])
            if isinstance(profiles, str):
                profiles = [profiles]
            node = PocNode(
                poc_id=entry["display_id"],
                poc_file=entry["poc_file"],
                poc_name=entry["poc_name"],
                category=entry.get("category", ""),
                severity=entry.get("severity", "Medium"),
                protocol=entry.get("protocol", ""),
                profiles=profiles,
                required_params=req,
                attack_surface=entry.get("attack_surface", "其他"),
                destructive_level=entry.get("destructive_level", "Safe"),
                is_disruptive=bool(entry.get("is_disruptive", False)),
            )
            self.nodes[node.poc_id] = node
        self._build_static_edges()
        self._activate_roots()

    def _build_static_edges(self):
        recon_ids = [n.poc_id for n in self.nodes.values() if n.category == "reconnaissance"]

        for node in self.nodes.values():
            if node.category == "reconnaissance":
                continue

            for req_param in node.required_params:
                for profile, grants in PROFILE_GRANTS.items():
                    if req_param in grants:
                        providers = [n for n in self.nodes.values()
                                     if profile in n.profiles and n.poc_id != node.poc_id]
                        for provider in providers:
                            self._add_edge(DependencyEdge(
                                source=provider.poc_id,
                                target=node.poc_id,
                                edge_type=EdgeType.PARAM_DEPENDENCY,
                                condition=f"grants:{req_param}",
                            ))

            for recon_id in recon_ids:
                recon_node = self.nodes[recon_id]
                if any(p in node.profiles for p in recon_node.profiles):
                    continue
                if node.required_params and "target_ip" in node.required_params:
                    self._add_edge(DependencyEdge(
                        source=recon_id,
                        target=node.poc_id,
                        edge_type=EdgeType.CATEGORY_PROGRESSION,
                        condition="recon_discovery",
                        weight=0.5,
                    ))

            node_cat_order = CATEGORY_ORDER.get(node.category, 2)
            if node_cat_order >= 2:
                for other in self.nodes.values():
                    if other.poc_id == node.poc_id:
                        continue
                    other_cat_order = CATEGORY_ORDER.get(other.category, 2)
                    if other_cat_order != node_cat_order - 1:
                        continue
                    if other.attack_surface == node.attack_surface or other.protocol == node.protocol:
                        self._add_edge(DependencyEdge(
                            source=other.poc_id,
                            target=node.poc_id,
                            edge_type=EdgeType.ATTACK_SURFACE_CHAIN,
                            weight=0.3,
                        ))

    def _add_edge(self, edge: DependencyEdge):
        existing = any(
            e.source == edge.source and e.target == edge.target and e.edge_type == edge.edge_type
            for e in self._adj[edge.source]
        )
        if not existing:
            self.edges.append(edge)
            self._adj[edge.source].append(edge)
            self._rev[edge.target].append(edge)

    def _activate_roots(self):
        for node in self.nodes.values():
            if node.category == "reconnaissance":
                node.state = PocState.ACTIVATED
                node.depth = 0
                continue

            if not node.required_params:
                node.state = PocState.ACTIVATED
                node.depth = 0
                continue

            if all(p in self.granted_params for p in node.required_params):
                can_run = True
                for profile in node.profiles:
                    if profile in ("can_extended", "can_gateway") and "can_interface" not in self.available_params:
                        can_run = False
                    elif profile in ("bluetooth", "bluetooth_recon") and "bluetooth_mac" not in self.available_params:
                        can_run = False
                    elif profile == "rf" and "frequency" not in self.available_params:
                        can_run = False
                if can_run:
                    node.state = PocState.ACTIVATED
                    node.depth = 0

    def on_poc_executed(self, poc_id: str, result: Dict[str, Any]):
        """PoC 执行完毕后的回调：更新状态、激活下游、记录历史。"""
        node = self.nodes.get(poc_id)
        if not node:
            return

        self._exec_order += 1
        vulnerable = bool(result.get("vulnerable", False))
        node.state = PocState.SUCCESS if vulnerable else PocState.FAILED
        node.execution_result = result
        node.evidence_score = float(result.get("evidence_score", 0.0))

        if node.depth == 0 and self._exec_order > 1:
            node.depth = self._exec_order - 1

        self.execution_history.append({
            "poc_id": poc_id,
            "poc_name": node.poc_name,
            "vulnerable": vulnerable,
            "severity": node.severity,
            "category": node.category,
            "depth": node.depth,
            "exec_order": self._exec_order,
        })

        if vulnerable:
            for profile in node.profiles:
                self.granted_profiles.add(profile)
                for param in PROFILE_GRANTS.get(profile, set()):
                    self.granted_params.add(param)

            discovered = result.get("discovered_params", {})
            if isinstance(discovered, dict):
                self.granted_params.update(discovered.keys())
                self.available_params.update(discovered)

            self._activate_downstream(poc_id)
            self._update_attack_paths(poc_id)

    def _activate_downstream(self, source_id: str):
        source_node = self.nodes[source_id]
        activated_count = 0

        for edge in self._adj.get(source_id, []):
            target = self.nodes.get(edge.target)
            if not target or target.state != PocState.PENDING:
                continue
            if self._can_activate(target):
                target.state = PocState.ACTIVATED
                target.depth = source_node.depth + 1
                target.activated_by = source_id
                activated_count += 1

        for node in self.nodes.values():
            if node.state != PocState.PENDING:
                continue
            if self._can_activate(node):
                node.state = PocState.ACTIVATED
                if node.depth == 0:
                    node.depth = source_node.depth + 1
                if not node.activated_by:
                    node.activated_by = source_id
                activated_count += 1

        return activated_count

    def _can_activate(self, node: PocNode) -> bool:
        if not node.required_params:
            return True
        if not all(p in self.granted_params for p in node.required_params):
            return False
        for profile in node.profiles:
            if profile in ("can_extended", "can_gateway") and "can_interface" not in self.available_params:
                return False
            if profile in ("bluetooth", "bluetooth_recon") and "bluetooth_mac" not in self.available_params:
                return False
            if profile == "rf" and "frequency" not in self.available_params:
                return False
        return True

    def _update_attack_paths(self, poc_id: str):
        node = self.nodes[poc_id]
        path_nodes = [poc_id]
        path_edges = []
        current = poc_id
        while True:
            cur = self.nodes[current]
            if not cur.activated_by:
                break
            parent = cur.activated_by
            if parent in path_nodes:
                break
            path_nodes.insert(0, parent)
            path_edges.insert(0, (parent, current))
            current = parent

        sev_sum = sum(
            SEVERITY_WEIGHT.get(self.nodes[n].severity.lower(), 2)
            for n in path_nodes if self.nodes[n].state == PocState.SUCCESS
        )
        successes = sum(1 for n in path_nodes if self.nodes[n].state == PocState.SUCCESS)
        self.attack_paths.append(AttackPath(
            nodes=path_nodes,
            edges=path_edges,
            total_severity=sev_sum,
            depth=len(path_nodes),
            success_rate=successes / max(len(path_nodes), 1),
        ))

    def next_poc_candidates(self, top_k: int = 5,
                            w_severity: float = 0.3,
                            w_depth: float = 0.2,
                            w_coverage: float = 0.25,
                            w_cost: float = 0.15,
                            w_risk: float = 0.1) -> List[Dict[str, Any]]:
        """从已激活未执行池中选出下一批候选 PoC，按综合价值排序。"""
        candidates = [n for n in self.nodes.values() if n.state == PocState.ACTIVATED]
        if not candidates:
            return []

        covered_cats = {h["category"] for h in self.execution_history}
        covered_surfaces = {
            self.nodes[h["poc_id"]].attack_surface
            for h in self.execution_history if h["poc_id"] in self.nodes
        }

        scored = []
        for node in candidates:
            sev_score = SEVERITY_WEIGHT.get(node.severity.lower(), 2) / 4.0
            depth_score = min(node.depth / 4.0, 1.0)
            cat_novel = 1.0 if node.category not in covered_cats else 0.0
            surf_novel = 1.0 if node.attack_surface not in covered_surfaces else 0.0
            coverage_score = 0.5 * cat_novel + 0.5 * surf_novel
            cost_score = self._compute_cost(node)
            risk_score = RISK_BY_DESTRUCTIVE.get(node.destructive_level, 0.2)
            if node.is_disruptive:
                risk_score = min(risk_score + 0.3, 1.0)

            value = (w_severity * sev_score
                     + w_depth * depth_score
                     + w_coverage * coverage_score
                     - w_cost * cost_score
                     - w_risk * risk_score)

            scored.append({
                "poc_id": node.poc_id,
                "poc_name": node.poc_name,
                "poc_file": node.poc_file,
                "category": node.category,
                "severity": node.severity,
                "attack_surface": node.attack_surface,
                "depth": node.depth,
                "value": round(value, 4),
                "severity_score": round(sev_score, 3),
                "depth_score": round(depth_score, 3),
                "coverage_score": round(coverage_score, 3),
                "cost_score": round(cost_score, 3),
                "risk_score": round(risk_score, 3),
                "activated_by": node.activated_by,
                "profiles": node.profiles,
            })

        scored.sort(key=lambda s: s["value"], reverse=True)
        return scored[:top_k]

    def _compute_cost(self, node: PocNode) -> float:
        cost = 0.0
        hardware_profiles = {"can_extended", "can_gateway", "rf", "bluetooth", "bluetooth_recon", "usb_adb"}
        if hardware_profiles & set(node.profiles):
            cost += 0.5
        if len(node.required_params) > 2:
            cost += 0.2
        return min(cost, 1.0)

    def get_graph_state(self) -> Dict[str, Any]:
        """返回当前图状态的完整快照，用于可视化和调试。"""
        state_counts = defaultdict(int)
        for n in self.nodes.values():
            state_counts[n.state.value] += 1

        return {
            "total_pocs": len(self.nodes),
            "state_distribution": dict(state_counts),
            "granted_params": sorted(self.granted_params),
            "granted_profiles": sorted(self.granted_profiles),
            "execution_history_count": len(self.execution_history),
            "attack_paths_count": len(self.attack_paths),
            "edges_count": len(self.edges),
        }

    def get_attack_graph(self) -> Dict[str, Any]:
        """生成最终攻击图，包含成功路径、节点与边信息，供前端可视化。"""
        success_nodes = [n for n in self.nodes.values() if n.state == PocState.SUCCESS]
        failed_nodes = [n for n in self.nodes.values() if n.state == PocState.FAILED]

        graph_nodes = []
        for n in success_nodes:
            graph_nodes.append({
                "id": n.poc_id,
                "label": n.poc_name,
                "category": n.category,
                "severity": n.severity,
                "attack_surface": n.attack_surface,
                "state": n.state.value,
                "depth": n.depth,
                "evidence_score": n.evidence_score,
            })

        graph_edges = []
        success_ids = {n.poc_id for n in success_nodes}
        for edge in self.edges:
            if edge.source in success_ids and edge.target in success_ids:
                graph_edges.append({
                    "source": edge.source,
                    "target": edge.target,
                    "type": edge.edge_type.value,
                    "weight": edge.weight,
                })
        for n in success_nodes:
            if n.activated_by and n.activated_by in success_ids:
                if not any(e["source"] == n.activated_by and e["target"] == n.poc_id for e in graph_edges):
                    graph_edges.append({
                        "source": n.activated_by,
                        "target": n.poc_id,
                        "type": EdgeType.EXECUTION_TRIGGER.value,
                        "weight": 1.0,
                    })

        longest_path = max(self.attack_paths, key=lambda p: p.total_severity) if self.attack_paths else None

        return {
            "nodes": graph_nodes,
            "edges": graph_edges,
            "critical_path": {
                "nodes": longest_path.nodes,
                "depth": longest_path.depth,
                "total_severity": longest_path.total_severity,
                "success_rate": longest_path.success_rate,
            } if longest_path else None,
            "stats": {
                "success_count": len(success_nodes),
                "failed_count": len(failed_nodes),
                "total_executed": len(self.execution_history),
                "max_depth": max((n.depth for n in success_nodes), default=0),
                "attack_surface_coverage": sorted({n.attack_surface for n in success_nodes}),
            },
        }


def next_poc_actions(candidate_pocs: List[Dict[str, Any]],
                     confirmed_findings: List[Dict[str, Any]],
                     executed_pocs: Optional[List[Dict[str, Any]]] = None,
                     available_params: Optional[Dict[str, str]] = None,
                     coverage_path: Optional[str] = None,
                     top_k: int = 5) -> Dict[str, Any]:
    """兼容 exploration_planner.next_exploration_actions 的接口，基于 PoC 依赖图排序。"""
    graph = PocDependencyGraph(available_params=available_params)
    if coverage_path:
        graph.load_from_coverage(coverage_path)

    for f in (confirmed_findings or []):
        poc_id = f.get("poc_id") or f.get("display_id") or f.get("name", "")
        if poc_id in graph.nodes:
            graph.on_poc_executed(poc_id, {
                "vulnerable": f.get("vulnerable", True),
                "evidence_score": f.get("evidence_score", 0),
            })

    for p in (executed_pocs or []):
        poc_id = p.get("poc_id") or p.get("display_id") or p.get("name", "")
        if poc_id in graph.nodes and graph.nodes[poc_id].state in (PocState.PENDING, PocState.ACTIVATED):
            graph.on_poc_executed(poc_id, {"vulnerable": False})

    actions = graph.next_poc_candidates(top_k=top_k)
    state = graph.get_graph_state()

    return {
        "actions": actions,
        "frontier_size": state["state_distribution"].get("activated", 0),
        "graph_state": state,
        "policy": "poc_dependency_graph",
    }


def run_dynamic_attack_path(coverage_path: str,
                            execute_fn: Callable[[Dict[str, Any]], Dict[str, Any]],
                            available_params: Optional[Dict[str, str]] = None,
                            budget: int = 50,
                            on_step: Optional[Callable[[Dict[str, Any]], None]] = None,
                            ) -> Dict[str, Any]:
    """在线闭环：初始化图 → 选择 PoC → 执行 → 反馈 → 激活下游 → 选择下一个 → 循环。

    execute_fn(poc_info) -> {"vulnerable": bool, "evidence_score": float, "discovered_params": dict, ...}
    """
    graph = PocDependencyGraph(available_params=available_params)
    graph.load_from_coverage(coverage_path)

    for step_idx in range(budget):
        candidates = graph.next_poc_candidates(top_k=1)
        if not candidates:
            break

        best = candidates[0]
        poc_id = best["poc_id"]
        node = graph.nodes[poc_id]
        node.state = PocState.RUNNING

        poc_info = {
            "poc_id": poc_id,
            "poc_file": node.poc_file,
            "poc_name": node.poc_name,
            "category": node.category,
            "severity": node.severity,
            "required_params": node.required_params,
            "profiles": node.profiles,
            "parameters": {p: graph.available_params.get(p, "") for p in node.required_params},
        }

        result = execute_fn(poc_info) or {}
        graph.on_poc_executed(poc_id, result)

        step_record = {
            "step": step_idx + 1,
            "poc_id": poc_id,
            "poc_name": node.poc_name,
            "category": node.category,
            "vulnerable": bool(result.get("vulnerable")),
            "value": best["value"],
            "depth": node.depth,
        }
        if on_step:
            on_step(step_record)

    attack_graph = graph.get_attack_graph() if any(
        n.state == PocState.SUCCESS for n in graph.nodes.values()
    ) else None

    return {
        "execution_history": graph.execution_history,
        "attack_graph": attack_graph,
        "graph_state": graph.get_graph_state(),
        "probes_used": len(graph.execution_history),
        "attack_paths": [
            {"nodes": p.nodes, "depth": p.depth,
             "total_severity": p.total_severity, "success_rate": p.success_rate}
            for p in graph.attack_paths
        ],
    }

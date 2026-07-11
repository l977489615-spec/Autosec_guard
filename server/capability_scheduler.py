"""Evidence-gated incremental PoC scheduler.

The scheduler is deliberately deterministic: LLM output cannot create facts,
unlock PoCs, or widen target scope. Only confirmed execution evidence grants
descriptor-declared capabilities.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


CONFIRMED_VERDICTS = {"confirmed_vulnerable", "manual_confirmed_vulnerable", "auto_confirmed_vulnerable"}


def _listify(value: Any) -> list[str]:
    if isinstance(value, str):
        return [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(part).strip() for part in value if str(part).strip()]
    return []


@dataclass(frozen=True)
class CapabilityFact:
    capability: str
    subject: str
    source_poc: str
    confidence: float = 1.0
    evidence_status: str = "confirmed"

    @property
    def key(self) -> tuple[str, str]:
        return self.subject, self.capability


@dataclass
class CapabilityDescriptor:
    poc_file: str
    requires_all: set[str] = field(default_factory=set)
    requires_any: set[str] = field(default_factory=set)
    excludes: set[str] = field(default_factory=set)
    grants_on_confirmed: set[str] = field(default_factory=set)
    required_params: list[str] = field(default_factory=list)
    severity: str = "Medium"
    destructive_level: str = "Safe"


class CapabilityScheduler:
    def __init__(self, descriptors: Iterable[dict[str, Any]], subject: str):
        self.subject = str(subject)
        self.descriptors: dict[str, CapabilityDescriptor] = {}
        self.facts: dict[tuple[str, str], CapabilityFact] = {}
        self.executed: set[str] = set()
        self.unlocked: set[str] = set()
        self.scheduled: set[str] = set()
        self.history: list[dict[str, Any]] = []
        for raw in descriptors:
            poc_file = str(raw.get("poc_file") or "").replace("\\", "/").strip()
            if not poc_file:
                continue
            descriptor = CapabilityDescriptor(
                poc_file=poc_file,
                requires_all=set(_listify(raw.get("requires_capabilities"))),
                requires_any=set(_listify(raw.get("requires_any_capabilities"))),
                excludes=set(_listify(raw.get("excludes_capabilities"))),
                grants_on_confirmed=set(_listify(raw.get("grants_on_confirmed"))),
                required_params=_listify(raw.get("required_params")),
                severity=str(raw.get("severity") or "Medium"),
                destructive_level=str(raw.get("destructive_level") or "Safe"),
            )
            self.descriptors[poc_file] = descriptor

    def seed(self, capabilities: Iterable[str], source: str = "session_input") -> None:
        for capability in capabilities:
            value = str(capability).strip()
            if value:
                fact = CapabilityFact(value, self.subject, source)
                self.facts[fact.key] = fact

    def _is_confirmed(self, result: dict[str, Any]) -> bool:
        if result.get("vulnerable") is not True:
            return False
        if result.get("requires_human_review") or result.get("verification_status") == "pending_manual_review":
            return False
        status = str(result.get("verification_status") or result.get("verdict") or "").strip().lower()
        if status and status in {"inconclusive", "needs_retest", "execution_error", "error"}:
            return False
        if status.startswith("manual_") and status not in CONFIRMED_VERDICTS:
            return False
        return True

    def observe(self, poc_file: str, result: dict[str, Any]) -> list[CapabilityFact]:
        normalized = str(poc_file).replace("\\", "/")
        self.executed.add(normalized)
        descriptor = self.descriptors.get(normalized)
        if descriptor is None or not self._is_confirmed(result):
            self.history.append({"poc_file": normalized, "confirmed": False, "granted": []})
            return []
        added: list[CapabilityFact] = []
        for capability in sorted(descriptor.grants_on_confirmed):
            fact = CapabilityFact(capability, self.subject, normalized)
            if fact.key not in self.facts:
                self.facts[fact.key] = fact
                added.append(fact)
        self.history.append({
            "poc_file": normalized,
            "confirmed": True,
            "granted": [fact.capability for fact in added],
        })
        return added

    def evaluate_delta(self, excluded: Iterable[str] = ()) -> list[dict[str, Any]]:
        excluded_set = {str(value).replace("\\", "/") for value in excluded}
        available = {capability for subject, capability in self.facts if subject == self.subject}
        candidates: list[dict[str, Any]] = []
        for descriptor in self.descriptors.values():
            if not descriptor.requires_all and not descriptor.requires_any:
                continue
            if descriptor.poc_file in self.executed or descriptor.poc_file in self.scheduled or descriptor.poc_file in excluded_set:
                continue
            if not descriptor.requires_all.issubset(available):
                continue
            if descriptor.requires_any and descriptor.requires_any.isdisjoint(available):
                continue
            if descriptor.excludes.intersection(available):
                continue
            self.unlocked.add(descriptor.poc_file)
            candidates.append({
                "poc_file": descriptor.poc_file,
                "requires_all": sorted(descriptor.requires_all),
                "requires_any": sorted(descriptor.requires_any),
                "unlocked_by": sorted((descriptor.requires_all | descriptor.requires_any).intersection(available)),
                "required_params": descriptor.required_params,
                "severity": descriptor.severity,
                "destructive_level": descriptor.destructive_level,
            })
        candidates.sort(key=lambda item: (
            {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(item["severity"], 4),
            item["poc_file"],
        ))
        return candidates

    def mark_scheduled(self, poc_files: Iterable[str]) -> None:
        self.scheduled.update(str(value).replace("\\", "/") for value in poc_files)

    def snapshot(self) -> dict[str, Any]:
        graph_nodes = [
            {"id": f"fact:{fact.subject}:{fact.capability}", "type": "fact", "label": fact.capability,
             "subject": fact.subject, "status": fact.evidence_status, "source_poc": fact.source_poc}
            for fact in sorted(self.facts.values(), key=lambda value: value.capability)
        ]
        graph_edges: list[dict[str, Any]] = []
        for descriptor in self.descriptors.values():
            if not (descriptor.requires_all or descriptor.requires_any or descriptor.grants_on_confirmed):
                continue
            poc_status = "executed" if descriptor.poc_file in self.executed else (
                "scheduled" if descriptor.poc_file in self.scheduled else (
                    "unlocked" if descriptor.poc_file in self.unlocked else "locked"
                )
            )
            graph_nodes.append({"id": f"poc:{descriptor.poc_file}", "type": "poc", "label": descriptor.poc_file, "status": poc_status})
            for capability in sorted(descriptor.requires_all | descriptor.requires_any):
                graph_edges.append({
                    "source": f"fact:{self.subject}:{capability}", "target": f"poc:{descriptor.poc_file}",
                    "type": "requires_any" if capability in descriptor.requires_any else "requires_all",
                })
            for capability in sorted(descriptor.grants_on_confirmed):
                graph_edges.append({
                    "source": f"poc:{descriptor.poc_file}", "target": f"fact:{self.subject}:{capability}",
                    "type": "grants_on_confirmed",
                })
        return {
            "subject": self.subject,
            "facts": [
                {
                    "capability": fact.capability,
                    "subject": fact.subject,
                    "source_poc": fact.source_poc,
                    "confidence": fact.confidence,
                    "evidence_status": fact.evidence_status,
                }
                for fact in sorted(self.facts.values(), key=lambda value: value.capability)
            ],
            "executed": sorted(self.executed),
            "unlocked": sorted(self.unlocked),
            "scheduled": sorted(self.scheduled),
            "history": list(self.history),
            "nodes": graph_nodes,
            "edges": graph_edges,
        }

    def hydrate(self, snapshot: dict[str, Any]) -> None:
        if not isinstance(snapshot, dict) or str(snapshot.get("subject") or self.subject) != self.subject:
            return
        for raw in snapshot.get("facts") or []:
            if not isinstance(raw, dict) or not raw.get("capability"):
                continue
            fact = CapabilityFact(
                capability=str(raw["capability"]),
                subject=self.subject,
                source_poc=str(raw.get("source_poc") or "restored_checkpoint"),
                confidence=float(raw.get("confidence") or 1.0),
                evidence_status=str(raw.get("evidence_status") or "confirmed"),
            )
            self.facts[fact.key] = fact
        self.executed.update(str(value).replace("\\", "/") for value in snapshot.get("executed") or [])
        self.unlocked.update(str(value).replace("\\", "/") for value in snapshot.get("unlocked") or [])
        self.scheduled.update(str(value).replace("\\", "/") for value in snapshot.get("scheduled") or [])
        if isinstance(snapshot.get("history"), list):
            self.history = list(snapshot["history"])

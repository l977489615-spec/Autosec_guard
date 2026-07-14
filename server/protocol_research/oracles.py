"""Anomaly oracles — single noisy events are never vulnerabilities."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .transport import ExchangeResult


@dataclass
class OracleVerdict:
    anomaly_score: float
    hits: list[str]
    inconclusive: bool
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "anomaly_score": self.anomaly_score,
            "hits": list(self.hits),
            "inconclusive": self.inconclusive,
            "notes": list(self.notes),
        }


def score_anomaly(
    *,
    baseline: list[ExchangeResult],
    candidate: list[ExchangeResult],
    post_baseline: list[ExchangeResult] | None = None,
    health: dict[str, Any] | None = None,
) -> OracleVerdict:
    hits: list[str] = []
    notes: list[str] = []
    score = 0.0
    health = health or {}

    baseline_ok = all(item.ok for item in baseline) if baseline else False
    if not baseline:
        notes.append("missing baseline — cannot claim vulnerability")
        return OracleVerdict(0.0, [], True, notes)

    if not baseline_ok:
        notes.append("unstable baseline — environment inconclusive")
        return OracleVerdict(0.0, [], True, notes)

    # Weak signals alone never score as vulnerability evidence
    if candidate and any(not item.ok for item in candidate):
        notes.append("connection error observed — insufficient alone")
    if candidate and any(item.connection_state == "error" for item in candidate):
        notes.append("tcp error — may be normal rejection")

    # Service / process oracle
    if health.get("process_exited"):
        hits.append("service_unavailable:process_exited")
        score += 0.55
    if health.get("port_gone"):
        hits.append("service_unavailable:port_gone")
        score += 0.5
    if health.get("watchdog_reset"):
        hits.append("resource:watchdog_reset")
        score += 0.4

    # Response / baseline divergence after candidate
    post = post_baseline or []
    if post and baseline_ok and not all(item.ok for item in post):
        hits.append("baseline_divergence:post_fail")
        score += 0.35

    # Security property hints (explicit markers from health adapter only)
    for key, label, weight in (
        ("auth_bypass", "security:auth_bypass", 0.5),
        ("unauthorized_read", "security:unauthorized_read", 0.45),
        ("unauthorized_write", "security:unauthorized_write", 0.45),
        ("session_isolation_broken", "security:session_isolation", 0.4),
    ):
        if health.get(key):
            hits.append(label)
            score += weight

    # Resource oracle
    if float(health.get("memory_growth_ratio") or 0) >= 2.0:
        hits.append("resource:memory_growth")
        score += 0.25
    if float(health.get("cpu_anomaly_ratio") or 0) >= 3.0:
        hits.append("resource:cpu_anomaly")
        score += 0.2

    if health.get("environment_unstable"):
        score = max(0.0, score - 0.5)
        notes.append("environment_unstable penalty applied")
        return OracleVerdict(score, hits, True, notes)

    # Single timeout / reset / new response: never enough
    if not hits:
        notes.append("no strong oracle hit — not a vulnerability candidate")
        return OracleVerdict(0.0, [], False, notes)

    return OracleVerdict(min(1.0, score), hits, False, notes)


def is_strong_candidate(verdict: OracleVerdict, *, threshold: float = 0.55) -> bool:
    return (not verdict.inconclusive) and verdict.anomaly_score >= threshold and bool(verdict.hits)

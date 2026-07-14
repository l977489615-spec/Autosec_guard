"""Baseline ↔ candidate reproduction protocol."""
from __future__ import annotations

import time
import uuid
from typing import Any, Callable

from .models import AnomalyCandidate
from .oracles import OracleVerdict, is_strong_candidate, score_anomaly
from .transport import ExchangeResult


HealthFn = Callable[[], dict[str, Any]]
PlayFn = Callable[[list[str]], list[ExchangeResult]]
RecoverFn = Callable[[], None]


def reproduce_anomaly(
    *,
    baseline_messages: list[str],
    candidate_messages: list[str],
    play: PlayFn,
    health: HealthFn | None = None,
    recover: RecoverFn | None = None,
    attempts: int = 3,
    required_hits: int = 2,
    seed_id: str = "",
) -> AnomalyCandidate:
    health_fn = health or (lambda: {})
    recover_fn = recover or (lambda: None)
    consistent_hits = 0
    last_verdict: OracleVerdict | None = None
    evidence_rounds: list[dict[str, Any]] = []

    for attempt in range(1, attempts + 1):
        baseline = play(baseline_messages)
        pre_health = health_fn()
        if pre_health.get("environment_unstable") or not all(item.ok for item in baseline):
            return AnomalyCandidate(
                anomaly_id=f"ANOM-{uuid.uuid4().hex[:8]}",
                status="inconclusive",
                score=0.0,
                oracle_hits=[],
                seed_id=seed_id,
                messages_hex=list(candidate_messages),
                evidence={"reason": "unstable_baseline", "attempt": attempt},
            )

        candidate = play(candidate_messages)
        mid_health = health_fn()
        recover_fn()
        post = play(baseline_messages)
        post_health = health_fn()

        merged_health = {**post_health, **{k: v for k, v in mid_health.items() if v}}
        verdict = score_anomaly(
            baseline=baseline,
            candidate=candidate,
            post_baseline=post,
            health=merged_health,
        )
        last_verdict = verdict
        evidence_rounds.append(
            {
                "attempt": attempt,
                "verdict": verdict.to_dict(),
                "candidate": [c.to_dict() for c in candidate],
                "post_baseline_ok": all(p.ok for p in post),
            }
        )
        if is_strong_candidate(verdict):
            consistent_hits += 1

    anomaly_id = f"ANOM-{uuid.uuid4().hex[:8]}"
    if last_verdict is None:
        status = "observed_once"
        score = 0.0
        hits: list[str] = []
    elif consistent_hits >= required_hits:
        status = "reproduced"
        score = last_verdict.anomaly_score
        hits = last_verdict.hits
    elif consistent_hits == 1:
        status = "reproduction_pending"
        score = last_verdict.anomaly_score
        hits = last_verdict.hits
    elif last_verdict.inconclusive:
        status = "inconclusive"
        score = last_verdict.anomaly_score
        hits = last_verdict.hits
    else:
        status = "observed_once"
        score = last_verdict.anomaly_score
        hits = last_verdict.hits

    return AnomalyCandidate(
        anomaly_id=anomaly_id,
        status=status,
        score=score,
        oracle_hits=hits,
        seed_id=seed_id,
        messages_hex=list(candidate_messages),
        evidence={
            "attempts": attempts,
            "consistent_hits": consistent_hits,
            "rounds": evidence_rounds,
            "recorded_at": time.time(),
        },
    )

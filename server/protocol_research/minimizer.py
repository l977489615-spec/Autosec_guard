"""Delta-debugging style input minimization for reproduced anomalies."""
from __future__ import annotations

from typing import Callable

from .models import AnomalyCandidate
from .reproducer import reproduce_anomaly
from .transport import ExchangeResult


PlayFn = Callable[[list[str]], list[ExchangeResult]]


def minimize_candidate(
    *,
    baseline_messages: list[str],
    candidate: AnomalyCandidate,
    play: PlayFn,
    attempts: int = 2,
    required_hits: int = 2,
) -> AnomalyCandidate:
    """Shrink session then shrink final payload while preserving reproduction."""
    if candidate.status != "reproduced":
        return candidate

    messages = list(candidate.messages_hex)
    # 1) Drop preceding messages from the front while reproduction holds
    while len(messages) > 1:
        trial = messages[1:]
        result = reproduce_anomaly(
            baseline_messages=baseline_messages,
            candidate_messages=trial,
            play=play,
            attempts=attempts,
            required_hits=required_hits,
            seed_id=candidate.seed_id,
        )
        if result.status == "reproduced":
            messages = trial
            candidate = result
        else:
            break

    # 2) Shorten the final trigger payload by halves
    if messages:
        payload = messages[-1]
        raw = bytes.fromhex(payload)
        lo, hi = 1, len(raw)
        best = raw
        while lo < hi:
            mid = (lo + hi) // 2
            trial_raw = best[:mid]
            trial_msgs = list(messages[:-1]) + [trial_raw.hex()]
            result = reproduce_anomaly(
                baseline_messages=baseline_messages,
                candidate_messages=trial_msgs,
                play=play,
                attempts=attempts,
                required_hits=required_hits,
                seed_id=candidate.seed_id,
            )
            if result.status == "reproduced":
                best = trial_raw
                messages = trial_msgs
                candidate = result
                hi = mid
            else:
                lo = mid + 1

    candidate.status = "minimized"
    candidate.messages_hex = messages
    candidate.evidence = {
        **(candidate.evidence or {}),
        "minimized": True,
        "final_message_count": len(messages),
        "final_trigger_bytes": len(bytes.fromhex(messages[-1])) if messages else 0,
    }
    return candidate

"""Unknown-protocol research engine.

Agent layers decide and orchestrate. Deterministic algorithms in this package
perform corpus handling, format/state inference, mutation, oracles, and
reproduction. Large models must never author or execute arbitrary attack code.
"""
from __future__ import annotations

from .campaign import (
    FuzzGateDecision,
    evaluate_active_fuzz_gates,
    run_offline_inference,
    run_stateful_fuzz_campaign,
)
from .models import (
    AnomalyCandidate,
    CorpusDocument,
    FieldSpec,
    MessageRecord,
    ProtocolModel,
    ProtocolTestPlan,
    ReplayPocManifest,
    SeedSpec,
    SessionRecord,
    StateTransition,
    SymbolSpec,
)

__all__ = [
    "AnomalyCandidate",
    "CorpusDocument",
    "FieldSpec",
    "FuzzGateDecision",
    "MessageRecord",
    "ProtocolModel",
    "ProtocolTestPlan",
    "ReplayPocManifest",
    "SeedSpec",
    "SessionRecord",
    "StateTransition",
    "SymbolSpec",
    "evaluate_active_fuzz_gates",
    "run_offline_inference",
    "run_stateful_fuzz_campaign",
]

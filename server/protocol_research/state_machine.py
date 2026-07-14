"""Black-box protocol state-machine inference from observed sessions."""
from __future__ import annotations

import hashlib
from collections import Counter, defaultdict

from .message_clustering import assign_symbol
from .models import CorpusDocument, ProtocolModel, StateTransition, SymbolSpec


def response_state_signature(
    *,
    response_symbol: str,
    length: int,
    connection_state: str = "open",
    status_code: str = "",
) -> str:
    length_bucket = f"L{(length // 16) * 16}-{(length // 16) * 16 + 15}"
    material = "|".join([response_symbol, length_bucket, connection_state, status_code or "-"])
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
    return f"S-{digest}"


def infer_state_machine(corpus: CorpusDocument, symbols: list[SymbolSpec]) -> ProtocolModel:
    transitions_counter: Counter[tuple[str, str, str, str]] = Counter()
    states = {"S0"}
    notes: list[str] = []

    for session in corpus.sessions:
        state = "S0"
        pending_req: str | None = None
        for msg in session.messages:
            symbol = assign_symbol(msg, symbols)
            if msg.direction == "client_to_server":
                pending_req = symbol
                continue
            # server response
            next_state = response_state_signature(
                response_symbol=symbol,
                length=len(msg.data),
            )
            states.add(next_state)
            req = pending_req or "MSG-IMPLICIT"
            transitions_counter[(state, req, symbol, next_state)] += 1
            state = next_state
            pending_req = None

    # group by (from, request) to compute probabilities
    by_from_req: dict[tuple[str, str], int] = defaultdict(int)
    for (frm, req, _resp, _to), count in transitions_counter.items():
        by_from_req[(frm, req)] += count

    transitions: list[StateTransition] = []
    for (frm, req, resp, to), count in transitions_counter.items():
        total = by_from_req[(frm, req)] or 1
        transitions.append(
            StateTransition(
                from_state=frm,
                request_symbol=req,
                response_symbol=resp,
                to_state=to,
                observed_count=count,
                probability=round(count / total, 4),
            )
        )

    if not transitions:
        notes.append("insufficient request/response pairs; state machine is incomplete")
    notes.append("state signatures are black-box approximations — not internal process state")

    ordered_states = ["S0"] + sorted(s for s in states if s != "S0")
    return ProtocolModel(
        model_id=f"MODEL-{corpus.corpus_id}",
        corpus_id=corpus.corpus_id,
        symbols=symbols,
        states=ordered_states,
        transitions=sorted(transitions, key=lambda t: (-t.observed_count, t.from_state)),
        inference_notes=notes,
    )

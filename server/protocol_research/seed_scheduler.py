"""State-aware seed scheduling (AFLNet / StateAFL inspired, black-box MVP)."""
from __future__ import annotations

from .models import CorpusDocument, ProtocolModel, SeedSpec, bytes_to_hex


def build_seeds_from_sessions(corpus: CorpusDocument, model: ProtocolModel) -> list[SeedSpec]:
    seeds: list[SeedSpec] = []
    for index, session in enumerate(corpus.sessions):
        reqs = [m for m in session.messages if m.direction == "client_to_server"]
        if not reqs:
            continue
        # Walk observed transitions to approximate path
        state_path = ["S0"]
        symbols: list[str] = []
        state = "S0"
        for msg in reqs:
            # pick most common transition from current state matching any response later
            match = next(
                (t for t in model.transitions if t.from_state == state),
                None,
            )
            label = match.request_symbol if match else f"REQ-{len(symbols)}"
            symbols.append(label)
            if match:
                state = match.to_state
                state_path.append(state)
            else:
                state_path.append(state)
        seed = SeedSpec(
            seed_id=f"SEED-{index:03d}",
            target_state=state_path[-1],
            message_sequence=symbols,
            state_path=state_path,
            coverage={"states": len(set(state_path)), "transitions": max(0, len(state_path) - 1)},
            messages_hex=[bytes_to_hex(m.data) for m in reqs],
        )
        seed.score = score_seed(seed, rarity={})
        seeds.append(seed)
    return sorted(seeds, key=lambda s: s.score, reverse=True)


def score_seed(
    seed: SeedSpec,
    *,
    rarity: dict[str, float],
    alpha: float = 1.0,
    beta: float = 1.0,
    gamma: float = 1.2,
    epsilon: float = 0.3,
    lam: float = 0.2,
    mu: float = 0.05,
) -> float:
    new_states = float(seed.coverage.get("states", 0))
    new_trans = float(seed.coverage.get("transitions", 0))
    rare = sum(rarity.get(s, 0.0) for s in seed.state_path)
    depth = float(len(seed.state_path))
    cost = float(len(seed.messages_hex))
    instability = 0.0  # reserved for future feedback
    return (
        alpha * new_states
        + beta * new_trans
        + gamma * rare
        + epsilon * depth
        - lam * instability
        - mu * cost
    )

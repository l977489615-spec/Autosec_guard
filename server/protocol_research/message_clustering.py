"""Deterministic greedy message clustering (Netzob-style MVP)."""
from __future__ import annotations

from collections import defaultdict
from math import log2
from typing import Iterable

from .models import MessageRecord, SymbolSpec, bytes_to_hex


def _edit_distance(a: bytes, b: bytes) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def _ascii_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b < 127)
    return printable / len(data)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    return -sum((c / total) * log2(c / total) for c in counts if c)


def message_distance(a: bytes, b: bytes, *, prefix_n: int = 8) -> float:
    max_len = max(len(a), len(b), 1)
    edit = _edit_distance(a[:64], b[:64]) / max(min(len(a), 64), min(len(b), 64), 1)
    length_diff = abs(len(a) - len(b)) / max_len
    n = min(prefix_n, len(a), len(b))
    if n == 0:
        fixed = 1.0
    else:
        fixed = sum(1 for i in range(n) if a[i] != b[i]) / n
    type_diff = abs(_ascii_ratio(a) - _ascii_ratio(b)) + abs(_entropy(a) - _entropy(b)) / 8.0
    type_diff = min(1.0, type_diff)
    return 0.35 * edit + 0.25 * length_diff + 0.25 * fixed + 0.15 * type_diff


def cluster_messages(
    messages: Iterable[MessageRecord],
    *,
    threshold: float = 0.35,
) -> list[SymbolSpec]:
    by_direction: dict[str, list[MessageRecord]] = defaultdict(list)
    for msg in messages:
        by_direction[msg.direction].append(msg)

    symbols: list[SymbolSpec] = []
    counter = 0
    for direction, items in by_direction.items():
        clusters: list[list[MessageRecord]] = []
        for msg in items:
            placed = False
            for cluster in clusters:
                if message_distance(msg.data, cluster[0].data) <= threshold:
                    cluster.append(msg)
                    placed = True
                    break
            if not placed:
                clusters.append([msg])
        for cluster in clusters:
            counter += 1
            lengths = [len(m.data) for m in cluster]
            samples = [bytes_to_hex(m.data) for m in cluster[:8]]
            prefix = _common_prefix_label(cluster)
            symbol_id = f"MSG-{direction[:3].upper()}-{prefix or f'{counter:03d}'}"
            symbols.append(
                SymbolSpec(
                    symbol_id=symbol_id,
                    direction=direction,
                    sample_count=len(cluster),
                    length_range=[min(lengths), max(lengths)],
                    sample_hexes=samples,
                    confidence=min(0.95, 0.45 + 0.05 * len(cluster)),
                )
            )
    return symbols


def assign_symbol(message: MessageRecord, symbols: list[SymbolSpec]) -> str:
    best_id = "MSG-UNKNOWN"
    best_dist = 1.0
    for symbol in symbols:
        if symbol.direction != message.direction or not symbol.sample_hexes:
            continue
        sample = bytes.fromhex(symbol.sample_hexes[0])
        dist = message_distance(message.data, sample)
        if dist < best_dist:
            best_dist = dist
            best_id = symbol.symbol_id
    return best_id


def _common_prefix_label(cluster: list[MessageRecord]) -> str:
    if not cluster:
        return ""
    data = [m.data for m in cluster]
    n = min(len(d) for d in data)
    prefix = bytearray()
    for i in range(min(n, 2)):
        b = data[0][i]
        if all(d[i] == b for d in data):
            prefix.append(b)
        else:
            break
    return prefix.hex().upper() if prefix else ""

"""Per-symbol field inference with confidence scores (never asserted as fact)."""
from __future__ import annotations

from collections import Counter
from math import log2
from typing import Iterable

from .models import FieldSpec, SymbolSpec, hex_to_bytes


def _entropy(values: list[int]) -> float:
    if not values:
        return 0.0
    total = len(values)
    counts = Counter(values)
    return -sum((c / total) * log2(c / total) for c in counts.values())


def infer_fields_for_samples(samples: Iterable[bytes]) -> list[FieldSpec]:
    payloads = [s for s in samples if s]
    if not payloads:
        return []
    min_len = min(len(s) for s in payloads)
    if min_len == 0:
        return []

    columns: list[list[int]] = [[s[i] for s in payloads] for i in range(min_len)]
    fields: list[FieldSpec] = []
    i = 0
    while i < min_len:
        col = columns[i]
        unique = set(col)
        ent = _entropy(col)

        # Prefer multi-byte length detection even when the high byte looks static.
        if i + 1 < min_len:
            predicted = True
            for sample in payloads:
                claimed = int.from_bytes(sample[i : i + 2], "big")
                if claimed not in {len(sample), len(sample) - (i + 2), len(sample) - i}:
                    predicted = False
                    break
            if predicted and any(
                payloads[a][i : i + 2] != payloads[b][i : i + 2]
                for a in range(len(payloads))
                for b in range(a + 1, len(payloads))
            ):
                fields.append(
                    FieldSpec(
                        offset=i,
                        size=2,
                        type="length",
                        encoding="uint16_be",
                        confidence=0.86,
                    )
                )
                i += 2
                continue

        if len(unique) == 1:
            # grow static run
            j = i + 1
            while j < min_len and len(set(columns[j])) == 1 and columns[j][0] == col[0]:
                j += 1
            size = j - i
            ftype = "message_type" if i == 0 and size <= 2 else "static"
            fields.append(
                FieldSpec(
                    offset=i,
                    size=size,
                    type=ftype,
                    confidence=0.98 if ftype == "message_type" else 0.92,
                    constant_hex=bytes([col[0]] * size).hex() if size == 1 else bytes(payloads[0][i:j]).hex(),
                )
            )
            i = j
            continue

        if len(unique) <= 8 and ent < 2.5:
            fields.append(
                FieldSpec(offset=i, size=1, type="enum", confidence=0.8, notes=f"values={sorted(unique)[:8]}")
            )
            i += 1
            continue

        if i + 1 < min_len:
            predicted = True
            for sample in payloads:
                claimed = int.from_bytes(sample[i : i + 2], "big")
                if claimed not in {len(sample), len(sample) - (i + 2), len(sample) - i}:
                    predicted = False
                    break
            if predicted:
                fields.append(
                    FieldSpec(
                        offset=i,
                        size=2,
                        type="length",
                        encoding="uint16_be",
                        confidence=0.86,
                    )
                )
                i += 2
                continue

        if ent > 6.0 and len(unique) >= max(3, len(payloads) // 2):
            # fixed high-entropy slot → session/token candidate
            j = i + 1
            while j < min_len and j < i + 8 and _entropy(columns[j]) > 5.5:
                j += 1
            size = max(1, j - i)
            fields.append(
                FieldSpec(
                    offset=i,
                    size=size,
                    type="session_id",
                    confidence=0.72,
                )
            )
            i += size
            continue

        # monotonic counter heuristic
        if all(payloads[k][i] <= payloads[k + 1][i] for k in range(len(payloads) - 1)) and len(unique) > 1:
            fields.append(FieldSpec(offset=i, size=1, type="counter", confidence=0.65))
            i += 1
            continue

        fields.append(FieldSpec(offset=i, size=1, type="unknown", confidence=0.55))
        i += 1

    # trailing variable payload if lengths differ
    max_len = max(len(s) for s in payloads)
    if max_len > min_len:
        fields.append(
            FieldSpec(
                offset=min_len,
                size=-1,
                type="payload",
                confidence=0.61,
                notes="variable-length region beyond aligned prefix",
            )
        )
    elif fields and fields[-1].type == "unknown":
        # collapse trailing unknowns into payload
        start = fields[-1].offset
        while fields and fields[-1].type in {"unknown"}:
            start = fields[-1].offset
            fields.pop()
        fields.append(FieldSpec(offset=start, size=-1, type="payload", confidence=0.6))

    # checksum candidate: last 2–4 bytes vary with content and are not static
    if min_len >= 4 and fields:
        tail = columns[min_len - 2]
        if len(set(tail)) > 1 and _entropy(tail) > 3.0:
            fields.append(
                FieldSpec(
                    offset=min_len - 2,
                    size=2,
                    type="checksum",
                    confidence=0.45,
                    notes="trailing varying bytes — checksum candidate only",
                )
            )

    return fields


def enrich_symbols(symbols: list[SymbolSpec]) -> list[SymbolSpec]:
    enriched: list[SymbolSpec] = []
    for symbol in symbols:
        samples = [hex_to_bytes(h) for h in symbol.sample_hexes]
        fields = infer_fields_for_samples(samples)
        conf = symbol.confidence
        if fields:
            conf = min(0.97, (conf + sum(f.confidence for f in fields) / len(fields)) / 2)
        enriched.append(
            SymbolSpec(
                symbol_id=symbol.symbol_id,
                direction=symbol.direction,
                sample_count=symbol.sample_count,
                length_range=list(symbol.length_range),
                fields=fields,
                sample_hexes=list(symbol.sample_hexes),
                confidence=conf,
            )
        )
    return enriched

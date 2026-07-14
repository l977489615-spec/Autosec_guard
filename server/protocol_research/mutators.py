"""Field-aware, deterministic mutation engine — no LLM-authored bytes."""
from __future__ import annotations

from .models import FieldSpec, SymbolSpec, bytes_to_hex, hex_to_bytes


def mutate_message(
    data_hex: str,
    fields: list[FieldSpec] | None = None,
    *,
    max_variants: int = 16,
) -> list[str]:
    data = bytearray(hex_to_bytes(data_hex))
    if not data:
        return []
    variants: list[bytes] = []

    dynamic_fields = [
        f
        for f in (fields or [])
        if f.type in {"length", "session_id", "counter", "payload", "enum", "unknown", "checksum"}
        and f.size != 0
    ]

    # Prefer mutating dynamic fields
    for field in dynamic_fields:
        offset = field.offset
        size = len(data) - offset if field.size < 0 else field.size
        if offset < 0 or offset >= len(data) or size <= 0:
            continue
        end = min(len(data), offset + size)
        region = data[offset:end]

        variants.append(_splice(data, offset, end, bytes([0] * (end - offset))))
        variants.append(_splice(data, offset, end, bytes([0xFF] * (end - offset))))
        if size >= 2:
            overflow = (len(data) + 1).to_bytes(2, "big")
            variants.append(_splice(data, offset, min(end, offset + 2), overflow[: end - offset]))
        # bit flip first byte
        flipped = bytearray(region)
        if flipped:
            flipped[0] ^= 0xFF
            variants.append(_splice(data, offset, end, bytes(flipped)))
        # truncate field
        if end - offset > 1:
            variants.append(bytes(data[:offset] + data[offset + 1 :]))
        # duplicate field
        variants.append(bytes(data[:end] + region + data[end:]))

    # Structural mutations on whole message
    variants.append(bytes(data[: max(1, len(data) // 2)]))  # truncate
    variants.append(bytes(data + data[: min(8, len(data))]))  # append prefix
    if len(data) >= 2:
        swapped = bytearray(data)
        swapped[0], swapped[-1] = swapped[-1], swapped[0]
        variants.append(bytes(swapped))

    # Deduplicate & cap
    unique: list[str] = []
    seen: set[str] = set()
    original = bytes_to_hex(bytes(data))
    for item in variants:
        hx = bytes_to_hex(item)
        if hx == original or hx in seen:
            continue
        if len(item) > 4096:
            continue
        seen.add(hx)
        unique.append(hx)
        if len(unique) >= max_variants:
            break
    return unique


def mutate_seed_sequence(
    messages_hex: list[str],
    symbols: list[SymbolSpec] | None = None,
    *,
    max_cases: int = 32,
) -> list[list[str]]:
    """Produce stateful cases: preserve prefix path, mutate deepest message."""
    if not messages_hex:
        return []
    fields: list[FieldSpec] = []
    if symbols:
        # use fields from last client-like symbol with samples
        for sym in symbols:
            if sym.direction == "client_to_server" and sym.fields:
                fields = sym.fields
                break
    deep = messages_hex[-1]
    variants = mutate_message(deep, fields)
    cases: list[list[str]] = []
    for variant in variants:
        cases.append(list(messages_hex[:-1]) + [variant])
        if len(cases) >= max_cases:
            break
    # Order confusion: swap last two if possible
    if len(messages_hex) >= 2:
        swapped = list(messages_hex)
        swapped[-1], swapped[-2] = swapped[-2], swapped[-1]
        cases.append(swapped)
    # Missing precondition: drop first message
    if len(messages_hex) >= 2:
        cases.append(list(messages_hex[1:]))
    # Repeat last
    cases.append(list(messages_hex) + [messages_hex[-1]])
    # Dedup
    final: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    for case in cases:
        key = tuple(case)
        if key in seen:
            continue
        seen.add(key)
        final.append(case)
        if len(final) >= max_cases:
            break
    return final


def _splice(buf: bytearray, start: int, end: int, replacement: bytes) -> bytes:
    return bytes(buf[:start] + replacement + buf[end:])

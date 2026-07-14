"""Shared immutable-ish data models for the protocol research engine."""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any


DIRECTIONS = ("client_to_server", "server_to_client")
FIELD_TYPES = (
    "static",
    "message_type",
    "enum",
    "length",
    "session_id",
    "counter",
    "checksum",
    "payload",
    "unknown",
)

DEFAULT_MAX_MESSAGE_BYTES = 4096
DEFAULT_MAX_MESSAGES_PER_SESSION = 64
DEFAULT_MAX_SESSIONS = 128


def _sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def hex_to_bytes(data_hex: str) -> bytes:
    cleaned = "".join(str(data_hex or "").split())
    if len(cleaned) % 2:
        cleaned = "0" + cleaned
    return bytes.fromhex(cleaned)


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


@dataclass
class MessageRecord:
    index: int
    direction: str
    timestamp: float
    data_hex: str
    data_sha256: str = ""

    def __post_init__(self) -> None:
        raw = hex_to_bytes(self.data_hex)
        self.data_hex = bytes_to_hex(raw)
        if not self.data_sha256:
            self.data_sha256 = _sha256_hex(raw)

    @property
    def data(self) -> bytes:
        return hex_to_bytes(self.data_hex)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SessionRecord:
    session_id: str
    messages: list[MessageRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "messages": [m.to_dict() for m in self.messages],
        }


@dataclass
class CorpusDocument:
    corpus_id: str
    target: dict[str, Any]
    sessions: list[SessionRecord] = field(default_factory=list)
    source: str = "operator"
    created_at: float = field(default_factory=time.time)
    corpus_sha256: str = ""

    def freeze_hash(self) -> str:
        payload = json.dumps(self.to_dict(include_hash=False), sort_keys=True, separators=(",", ":"))
        self.corpus_sha256 = _sha256_hex(payload.encode("utf-8"))
        return self.corpus_sha256

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        body = {
            "corpus_id": self.corpus_id,
            "target": dict(self.target),
            "sessions": [s.to_dict() for s in self.sessions],
            "source": self.source,
            "created_at": self.created_at,
        }
        if include_hash:
            body["corpus_sha256"] = self.corpus_sha256
        return body


@dataclass
class FieldSpec:
    offset: int
    size: int
    type: str
    confidence: float
    constant_hex: str = ""
    encoding: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SymbolSpec:
    symbol_id: str
    direction: str
    sample_count: int
    length_range: list[int]
    fields: list[FieldSpec] = field(default_factory=list)
    sample_hexes: list[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "symbol_id": self.symbol_id,
            "direction": self.direction,
            "sample_count": self.sample_count,
            "length_range": list(self.length_range),
            "fields": [f.to_dict() for f in self.fields],
            "sample_hexes": list(self.sample_hexes),
            "confidence": self.confidence,
        }


@dataclass
class StateTransition:
    from_state: str
    request_symbol: str
    response_symbol: str
    to_state: str
    observed_count: int
    probability: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProtocolModel:
    model_id: str
    corpus_id: str
    symbols: list[SymbolSpec] = field(default_factory=list)
    states: list[str] = field(default_factory=list)
    transitions: list[StateTransition] = field(default_factory=list)
    inference_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "corpus_id": self.corpus_id,
            "symbols": [s.to_dict() for s in self.symbols],
            "states": list(self.states),
            "transitions": [t.to_dict() for t in self.transitions],
            "inference_notes": list(self.inference_notes),
        }


@dataclass
class SeedSpec:
    seed_id: str
    target_state: str
    message_sequence: list[str]
    state_path: list[str]
    coverage: dict[str, int] = field(default_factory=dict)
    score: float = 0.0
    messages_hex: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnomalyCandidate:
    anomaly_id: str
    status: str
    score: float
    oracle_hits: list[str] = field(default_factory=list)
    seed_id: str = ""
    messages_hex: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReplayPocManifest:
    schema_version: str
    poc_id: str
    source_campaign_id: str
    target_profile: dict[str, Any]
    preconditions: list[str]
    state_path: list[str]
    messages: list[dict[str, str]]
    oracle: dict[str, Any]
    reproduction: dict[str, Any]
    status: str = "candidate_poc"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProtocolTestPlan:
    """Stage-04 output: declarative plan only — never executable code."""

    task_index: int
    target_port: int
    mode: str  # fingerprint | offline_inference | stateful_fuzz
    profiles: list[str] = field(default_factory=list)
    fuzz_enabled: bool = False
    gate_reason: str = ""
    corpus_ref: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

"""Corpus manager — ingest, bound, and preserve raw protocol sessions."""
from __future__ import annotations

import time
import uuid
from typing import Any, Iterable

from .models import (
    DEFAULT_MAX_MESSAGE_BYTES,
    DEFAULT_MAX_MESSAGES_PER_SESSION,
    DEFAULT_MAX_SESSIONS,
    CorpusDocument,
    MessageRecord,
    SessionRecord,
    bytes_to_hex,
    hex_to_bytes,
)


class CorpusValidationError(ValueError):
    pass


class CorpusManager:
    def __init__(
        self,
        *,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        max_messages_per_session: int = DEFAULT_MAX_MESSAGES_PER_SESSION,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
    ) -> None:
        self.max_message_bytes = int(max_message_bytes)
        self.max_messages_per_session = int(max_messages_per_session)
        self.max_sessions = int(max_sessions)
        self._store: dict[str, CorpusDocument] = {}

    def create_from_sessions(
        self,
        *,
        target: dict[str, Any],
        sessions: Iterable[dict[str, Any] | SessionRecord],
        corpus_id: str = "",
        source: str = "operator",
    ) -> CorpusDocument:
        pinned = self._pin_target(target)
        normalized_sessions: list[SessionRecord] = []
        for raw in sessions:
            if len(normalized_sessions) >= self.max_sessions:
                break
            normalized_sessions.append(self._normalize_session(raw))
        if not normalized_sessions:
            raise CorpusValidationError("corpus requires at least one valid session")
        doc = CorpusDocument(
            corpus_id=corpus_id or f"CORPUS-{time.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}",
            target=pinned,
            sessions=normalized_sessions,
            source=source,
        )
        doc.freeze_hash()
        self._store[doc.corpus_id] = doc
        return doc

    def create_from_hex_dialog(
        self,
        *,
        target: dict[str, Any],
        turns: list[tuple[str, str]],
        session_id: str = "SESSION-001",
        source: str = "hex_dialog",
    ) -> CorpusDocument:
        """turns: list of (direction, data_hex)."""
        now = time.time()
        messages = [
            MessageRecord(index=i, direction=direction, timestamp=now + i * 0.01, data_hex=data_hex)
            for i, (direction, data_hex) in enumerate(turns)
        ]
        return self.create_from_sessions(
            target=target,
            sessions=[SessionRecord(session_id=session_id, messages=messages)],
            source=source,
        )

    def get(self, corpus_id: str) -> CorpusDocument | None:
        return self._store.get(corpus_id)

    def to_immutable_dict(self, corpus_id: str) -> dict[str, Any]:
        doc = self._store.get(corpus_id)
        if not doc:
            raise KeyError(corpus_id)
        return doc.to_dict()

    def _pin_target(self, target: dict[str, Any]) -> dict[str, Any]:
        ip = str(target.get("ip") or target.get("target_ip") or "").strip()
        port = int(target.get("port") or target.get("target_port") or 0)
        transport = str(target.get("transport") or "tcp").strip().lower()
        if not ip:
            raise CorpusValidationError("target.ip is required")
        if not 1 <= port <= 65535:
            raise CorpusValidationError("target.port must be 1..65535")
        if transport not in {"tcp", "udp"}:
            raise CorpusValidationError("target.transport must be tcp or udp")
        return {"ip": ip, "port": port, "transport": transport}

    def _normalize_session(self, raw: dict[str, Any] | SessionRecord) -> SessionRecord:
        if isinstance(raw, SessionRecord):
            messages = [self._normalize_message(m.to_dict(), default_index=m.index) for m in raw.messages]
            session_id = raw.session_id
        else:
            session_id = str(raw.get("session_id") or f"SESSION-{uuid.uuid4().hex[:6].upper()}")
            messages = []
            for idx, item in enumerate(raw.get("messages") or []):
                messages.append(self._normalize_message(item, default_index=idx))
        if not messages:
            raise CorpusValidationError(f"session {session_id} has no messages")
        if len(messages) > self.max_messages_per_session:
            messages = messages[: self.max_messages_per_session]
        return SessionRecord(session_id=session_id, messages=messages)

    def _normalize_message(self, raw: dict[str, Any] | MessageRecord, *, default_index: int) -> MessageRecord:
        if isinstance(raw, MessageRecord):
            data = raw.data
            direction = raw.direction
            index = raw.index
            timestamp = raw.timestamp
        else:
            direction = str(raw.get("direction") or "client_to_server").strip()
            if direction not in {"client_to_server", "server_to_client"}:
                raise CorpusValidationError(f"invalid message direction: {direction}")
            data_hex = str(raw.get("data_hex") or "")
            data = hex_to_bytes(data_hex)
            index = int(raw.get("index", default_index))
            timestamp = float(raw.get("timestamp") or time.time())
        if len(data) > self.max_message_bytes:
            raise CorpusValidationError(
                f"message exceeds max_message_bytes={self.max_message_bytes}"
            )
        return MessageRecord(
            index=index,
            direction=direction,
            timestamp=timestamp,
            data_hex=bytes_to_hex(data),
        )

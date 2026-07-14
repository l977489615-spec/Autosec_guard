"""Persistent protocol corpus store — versioned, validated, immutable on disk."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .corpus import CorpusManager, CorpusValidationError
from .models import CorpusDocument


class CorpusNotFoundError(KeyError):
    pass


class ProtocolCorpusStore:
    def __init__(self, root_dir: str | Path) -> None:
        self.root = Path(root_dir)
        self.root.mkdir(parents=True, exist_ok=True)
        self._manager = CorpusManager()

    def save(self, payload: dict[str, Any], *, user_id: int | None = None) -> CorpusDocument:
        doc = self._manager.create_from_sessions(
            target=payload.get("target") or {},
            sessions=payload.get("sessions") or [],
            corpus_id=str(payload.get("corpus_id") or ""),
            source=str(payload.get("source") or "operator"),
        )
        record = {
            "corpus_id": doc.corpus_id,
            "corpus_sha256": doc.corpus_sha256,
            "target": doc.target,
            "session_count": len(doc.sessions),
            "message_count": sum(len(s.messages) for s in doc.sessions),
            "source": doc.source,
            "created_at": doc.created_at,
            "saved_at": time.time(),
            "user_id": user_id,
            "document": doc.to_dict(include_hash=True),
        }
        path = self._path_for(doc.corpus_id)
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        return doc

    def get(self, corpus_id: str) -> CorpusDocument:
        path = self._path_for(corpus_id)
        if not path.exists():
            raise CorpusNotFoundError(corpus_id)
        record = json.loads(path.read_text(encoding="utf-8"))
        document = record.get("document") or {}
        return self._document_from_dict(document)

    def exists(self, corpus_id: str) -> bool:
        return self._path_for(corpus_id).exists()

    def summary(self, corpus_id: str) -> dict[str, Any]:
        path = self._path_for(corpus_id)
        if not path.exists():
            raise CorpusNotFoundError(corpus_id)
        record = json.loads(path.read_text(encoding="utf-8"))
        return {
            "corpus_id": record.get("corpus_id"),
            "corpus_sha256": record.get("corpus_sha256"),
            "target": record.get("target"),
            "session_count": record.get("session_count"),
            "message_count": record.get("message_count"),
            "source": record.get("source"),
            "created_at": record.get("created_at"),
            "saved_at": record.get("saved_at"),
        }

    def validate(self, corpus_id: str, *, target_ip: str = "", target_port: int | None = None) -> tuple[bool, str]:
        try:
            doc = self.get(corpus_id)
        except CorpusNotFoundError:
            return False, "corpus_not_found"
        if target_ip and str(doc.target.get("ip")) != str(target_ip):
            return False, "target_ip_mismatch"
        if target_port is not None and int(doc.target.get("port") or 0) != int(target_port):
            return False, "target_port_mismatch"
        if not doc.sessions:
            return False, "empty_corpus"
        return True, "ok"

    def _path_for(self, corpus_id: str) -> Path:
        safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in str(corpus_id))
        return self.root / f"{safe}.json"

    def _document_from_dict(self, document: dict[str, Any]) -> CorpusDocument:
        try:
            return self._manager.create_from_sessions(
                target=document.get("target") or {},
                sessions=document.get("sessions") or [],
                corpus_id=str(document.get("corpus_id") or ""),
                source=str(document.get("source") or "store"),
            )
        except CorpusValidationError as exc:
            raise CorpusNotFoundError(str(exc)) from exc


def default_corpus_store() -> ProtocolCorpusStore:
    base = Path(__file__).resolve().parents[1] / "data" / "protocol_corpus"
    return ProtocolCorpusStore(base)


def default_candidate_poc_dir() -> Path:
    path = Path(__file__).resolve().parents[1] / "data" / "candidate_pocs"
    path.mkdir(parents=True, exist_ok=True)
    return path

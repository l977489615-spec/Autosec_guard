"""Resolve inline corpus payloads or corpus_ref from the persistent store."""
from __future__ import annotations

import json
from typing import Any

from .corpus_store import CorpusNotFoundError, ProtocolCorpusStore, default_corpus_store
from .models import CorpusDocument


def _inline_corpus_payload(params: dict[str, Any]) -> dict[str, Any] | None:
    raw = params.get("corpus") or params.get("corpus_json")
    if raw is None:
        return None
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return None
    return raw if isinstance(raw, dict) else None


def resolve_corpus_for_params(
    params: dict[str, Any] | None,
    *,
    store: ProtocolCorpusStore | None = None,
    target_ip: str = "",
    target_port: int | None = None,
) -> CorpusDocument | None:
    params = params or {}
    inline = _inline_corpus_payload(params)
    if inline:
        from .corpus import CorpusManager

        manager = CorpusManager()
        target = dict(inline.get("target") or {})
        if target_ip:
            target.setdefault("ip", target_ip)
        if target_port is not None:
            target.setdefault("port", target_port)
        return manager.create_from_sessions(
            target=target,
            sessions=inline.get("sessions") or [],
            corpus_id=str(inline.get("corpus_id") or params.get("corpus_ref") or ""),
            source=str(inline.get("source") or "inline"),
        )

    corpus_ref = str(params.get("corpus_ref") or params.get("corpus_id") or "").strip()
    if not corpus_ref:
        return None
    store = store or default_corpus_store()
    try:
        doc = store.get(corpus_ref)
    except CorpusNotFoundError:
        return None
    if target_ip and str(doc.target.get("ip")) != str(target_ip):
        return None
    if target_port is not None and int(doc.target.get("port") or 0) != int(target_port):
        return None
    return doc


def corpus_available_for_params(
    params: dict[str, Any] | None,
    *,
    store: ProtocolCorpusStore | None = None,
    target_ip: str = "",
    target_port: int | None = None,
) -> bool:
    return resolve_corpus_for_params(
        params,
        store=store,
        target_ip=target_ip,
        target_port=target_port,
    ) is not None


def attach_resolved_corpus(params: dict[str, Any], *, store: ProtocolCorpusStore | None = None) -> dict[str, Any]:
    """Materialize corpus_ref into inline corpus for PoC execution (no LLM context bloat)."""
    params = dict(params or {})
    if _inline_corpus_payload(params):
        return params
    doc = resolve_corpus_for_params(params, store=store)
    if doc is None:
        return params
    params["corpus"] = doc.to_dict(include_hash=True)
    params.setdefault("corpus_ref", doc.corpus_id)
    return params

"""Shared execution/evidence metrics for platform vs baseline comparisons."""

from __future__ import annotations


OPERATOR_SKIP_MARKERS = (
    "skipped by operator",
    "requires explicit approval",
    "high-risk poc execution requires",
)


def operator_excluded(item: dict) -> bool:
    """Operator declined or bypassed high-risk execution; not an execution failure."""
    status = str(item.get("status") or "")
    if status in {"blocked", "authorization_denied", "skipped"}:
        return True
    error = str(item.get("error") or "").lower()
    return any(marker in error for marker in OPERATOR_SKIP_MARKERS)


def has_archived_evidence(item: dict) -> bool:
    if str(item.get("evidence") or "").strip():
        return True
    if str(item.get("evidence_file") or "").strip():
        return True
    if item.get("logs"):
        return True
    if item.get("vulnerable") is True:
        return True
    if item.get("requires_human_review") and str(item.get("status") or "") in {
        "pending_manual_review",
        "manual_review_completed",
        "completed",
        "vulnerable",
    }:
        return True
    return False


def classify_execution_item(item: dict) -> str:
    if operator_excluded(item):
        return "operator_excluded"
    status = str(item.get("status") or "")
    if status in {"failed", "error"}:
        return "failed"
    if status in {"blocked", "authorization_denied", "skipped"}:
        return "operator_excluded"
    return "completed"


def execution_sets(execution: list[dict], poc_id) -> dict[str, set[str]]:
    started: set[str] = set()
    completed: set[str] = set()
    evidence: set[str] = set()
    operator_skipped: set[str] = set()
    for item in execution:
        pid = poc_id(item)
        bucket = classify_execution_item(item)
        if bucket == "operator_excluded":
            operator_skipped.add(pid)
            continue
        started.add(pid)
        if bucket == "completed":
            completed.add(pid)
            if has_archived_evidence(item):
                evidence.add(pid)
    return {
        "started": started,
        "completed": completed,
        "evidence": evidence,
        "operator_skipped": operator_skipped,
    }

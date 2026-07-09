"""Shared execution/evidence metrics for platform vs baseline comparisons."""

from __future__ import annotations

import json
from pathlib import Path


OPERATOR_SKIP_MARKERS = (
    "skipped by operator",
    "requires explicit approval",
    "high-risk poc execution requires",
)

RISKY_VERIFICATION_STATUSES = {
    "auto_confirmed_vulnerable",
    "confirmed_vulnerable",
    "pending_manual_review",
    "manual_review_completed",
}

MANUAL_REVIEW_CONCLUDED_STATES = {
    "confirmed",
    "rejected",
    "confirmed_vulnerable",
    "confirmed_safe",
    "completed",
    "manual_review_completed",
}

# Reflector/Supervisor bookkeeping — not a fresh PoC execution in that round.
ORCHESTRATION_SKIP_STATUSES = {
    "skipped_by_reflector_reentry",
    "skipped_by_supervisor",
}


def operator_excluded(item: dict) -> bool:
    """Operator declined or bypassed high-risk execution; not an execution failure."""
    status = str(item.get("status") or "")
    if status in {"blocked", "authorization_denied", "skipped"}:
        return True
    error = str(item.get("error") or "").lower()
    return any(marker in error for marker in OPERATOR_SKIP_MARKERS)


def _repo_root(repo_root: Path | None) -> Path:
    return repo_root or Path(__file__).resolve().parents[1]


def _non_empty_logs(item: dict) -> bool:
    logs = item.get("logs")
    if isinstance(logs, list):
        return any(str(line).strip() for line in logs)
    if isinstance(logs, str):
        return bool(logs.strip())
    return False


def _structured_result(item: dict) -> bool:
    if any(item.get(key) is not None for key in ("success", "vulnerable", "http_status", "trace_id")):
        return True
    status = str(item.get("status") or "")
    if status and status not in {"pending", "queued", "running"}:
        return True
    for branch in item.get("branch_results") or []:
        if branch.get("success") is not None or branch.get("vulnerable") is not None:
            return True
        if str(branch.get("trace_id") or "").strip():
            return True
    return False


def _execution_trace(item: dict) -> bool:
    if _non_empty_logs(item):
        return True
    if str(item.get("evidence_file") or "").strip():
        return True
    for branch in item.get("branch_results") or []:
        if _non_empty_logs(branch):
            return True
        if branch.get("success") is not None and str(branch.get("trace_id") or "").strip():
            return True
    return False


def _manual_review_concluded(manual_review: object) -> bool:
    if not isinstance(manual_review, dict):
        return False
    state = str(manual_review.get("state") or "")
    if state in {"", "pending", "not_started"}:
        return False
    if state in MANUAL_REVIEW_CONCLUDED_STATES:
        return True
    return bool(str(manual_review.get("conclusion") or manual_review.get("verdict") or "").strip())


def _collect_evidence_texts(item: dict) -> list[str]:
    texts = [str(item.get("evidence") or ""), str(item.get("protocol_response") or "")]
    for branch in item.get("branch_results") or []:
        texts.append(str(branch.get("evidence") or ""))
        texts.append(str(branch.get("protocol_response") or ""))
    return [text for text in texts if text.strip()]


def _substantive_artifact(item: dict) -> bool:
    if _collect_evidence_texts(item):
        return True
    if item.get("screenshot") or item.get("screenshot_file"):
        return True
    if str(item.get("artifact_file") or "").strip():
        return True
    if str(item.get("evidence_file") or "").strip():
        return True
    for source in (item, *(item.get("branch_results") or [])):
        manual_review = source.get("manual_review")
        if _manual_review_concluded(manual_review):
            state = str((manual_review or {}).get("state") or "")
            if state not in {"not_required", "pending"}:
                return True
    return False


def _is_risk_finding(item: dict) -> bool:
    if item.get("vulnerable") is True:
        return True
    if item.get("requires_human_review"):
        return True
    status = str(item.get("status") or "")
    if status in {"vulnerable", "pending_manual_review"}:
        return True
    if str(item.get("verification_status") or "") in RISKY_VERIFICATION_STATUSES:
        return True
    for branch in item.get("branch_results") or []:
        if branch.get("vulnerable") is True:
            return True
        if branch.get("requires_human_review"):
            return True
        if str(branch.get("verification_status") or "") in RISKY_VERIFICATION_STATUSES:
            return True
    return False


def merge_evidence_artifact(item: dict, *, repo_root: Path | None = None) -> dict:
    merged = dict(item)
    evidence_file = str(item.get("evidence_file") or "").strip()
    if evidence_file:
        path = Path(evidence_file)
        if not path.is_absolute():
            path = _repo_root(repo_root) / evidence_file
        if path.is_file():
            try:
                artifact = json.loads(path.read_text(encoding="utf-8"))
                merged = {
                    **artifact,
                    **{key: value for key, value in merged.items() if value is not None and value != ""},
                }
            except (OSError, json.JSONDecodeError):
                pass
    preferred_branch = str(item.get("branch") or "primary")
    for branch in item.get("branch_results") or []:
        if str(branch.get("branch") or "") not in {preferred_branch, "primary"}:
            continue
        for key, value in branch.items():
            if value is not None and value != "" and (key not in merged or not merged.get(key)):
                merged[key] = value
    return merged


def _load_poc_run_artifact(
    poc_name: str,
    target_id: str,
    evidence_root: Path | None,
) -> dict | None:
    if not evidence_root or not poc_name or not target_id:
        return None
    run_dir = evidence_root / target_id / "poc_runs"
    if not run_dir.is_dir():
        return None
    short = Path(str(poc_name)).name.replace(".py", "")
    for path in run_dir.glob("*.json"):
        if short in path.name:
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return None
    return None


def merge_agent_execution_artifact(
    item: dict,
    *,
    target_id: str = "",
    evidence_root: Path | None = None,
    repo_root: Path | None = None,
) -> dict:
    """Merge inline evidence, evidence_file, and platform poc_runs sidecar when present."""
    merged = merge_evidence_artifact(item, repo_root=repo_root)
    poc_name = str(item.get("poc_name") or item.get("poc_file") or "")
    artifact = _load_poc_run_artifact(poc_name, target_id, evidence_root)
    if artifact:
        merged = {
            **artifact,
            **{key: value for key, value in merged.items() if value is not None and value != ""},
        }
    return merged


def has_l2_archived_evidence(item: dict, *, repo_root: Path | None = None) -> bool:
    merged = merge_evidence_artifact(item, repo_root=repo_root)
    return _execution_trace(merged) and _structured_result(merged)


def has_l3_evidence(
    item: dict,
    *,
    target_id: str = "",
    evidence_root: Path | None = None,
    repo_root: Path | None = None,
) -> bool:
    """L3 evidence: execution trace + structured result + substantive interaction material."""
    merged = merge_agent_execution_artifact(
        item,
        target_id=target_id,
        evidence_root=evidence_root,
        repo_root=repo_root,
    )
    if not (_execution_trace(merged) and _structured_result(merged)):
        return False
    if _substantive_artifact(merged):
        return True
    return not _is_risk_finding(merged) and _non_empty_logs(merged)


def has_auditable_evidence(
    item: dict,
    *,
    target_id: str = "",
    evidence_root: Path | None = None,
    repo_root: Path | None = None,
) -> bool:
    """Backward-compatible alias for L3 evidence checks."""
    return has_l3_evidence(
        item,
        target_id=target_id,
        evidence_root=evidence_root,
        repo_root=repo_root,
    )


def poc_run_artifact_exists(poc_name: str, target_id: str, evidence_root: Path | None) -> bool:
    if not evidence_root or not poc_name or not target_id:
        return False
    run_dir = evidence_root / target_id / "poc_runs"
    if not run_dir.is_dir():
        return False
    short = Path(str(poc_name)).name.replace(".py", "")
    return any(short in path.name for path in run_dir.glob("*.json"))


def _artifact_path_exists(path_text: str, *, repo_root: Path) -> bool:
    text = str(path_text or "").strip()
    if not text:
        return False
    path = Path(text)
    if not path.is_absolute():
        path = repo_root / path
    return path.is_file()


def _has_file_artifact(
    merged: dict,
    *,
    target_id: str,
    evidence_root: Path | None,
    repo_root: Path,
) -> bool:
    if _artifact_path_exists(str(merged.get("artifact_file") or ""), repo_root=repo_root):
        return True
    if _artifact_path_exists(str(merged.get("evidence_file") or ""), repo_root=repo_root):
        return True
    poc_name = str(merged.get("poc_name") or merged.get("poc_file") or "")
    return poc_run_artifact_exists(poc_name, target_id, evidence_root)


def _has_audit_record(merged: dict) -> bool:
    for source in (merged, *(merged.get("branch_results") or [])):
        manual_review = source.get("manual_review")
        if isinstance(manual_review, dict):
            state = str(manual_review.get("state") or "").strip()
            if state and state not in {"pending", "not_started"}:
                return True
            if _manual_review_concluded(manual_review):
                return True
        if str(source.get("authorization_id") or source.get("approval_id") or "").strip():
            return True
    trace_id = str(merged.get("trace_id") or "").strip()
    return bool(trace_id and trace_id != "agent_auto")


def has_l4_evidence(
    item: dict,
    *,
    target_id: str = "",
    evidence_root: Path | None = None,
    repo_root: Path | None = None,
) -> bool:
    """L4 evidence: L3 + on-disk file artifact (poc_run sidecar or artifact path)."""
    root = _repo_root(repo_root)
    if not has_l3_evidence(
        item,
        target_id=target_id,
        evidence_root=evidence_root,
        repo_root=root,
    ):
        return False
    merged = merge_agent_execution_artifact(
        item,
        target_id=target_id,
        evidence_root=evidence_root,
        repo_root=root,
    )
    return _has_file_artifact(
        merged,
        target_id=target_id,
        evidence_root=evidence_root,
        repo_root=root,
    )


def has_l5_evidence(
    item: dict,
    *,
    target_id: str = "",
    evidence_root: Path | None = None,
    repo_root: Path | None = None,
) -> bool:
    """L5 evidence for paper Tables 4/6 and Fig.4: file artifact + audit record."""
    root = _repo_root(repo_root)
    if not has_l4_evidence(
        item,
        target_id=target_id,
        evidence_root=evidence_root,
        repo_root=root,
    ):
        return False
    merged = merge_agent_execution_artifact(
        item,
        target_id=target_id,
        evidence_root=evidence_root,
        repo_root=root,
    )
    return _has_audit_record(merged)


def scan_row_has_evidence(row: dict, *, repo_root: Path | None = None) -> bool:
    """L2 effective evidence: execution trace + structured result."""
    return has_l2_archived_evidence(row, repo_root=repo_root)


def has_archived_evidence(
    item: dict,
    *,
    target_id: str = "",
    evidence_root: Path | None = None,
    repo_root: Path | None = None,
) -> bool:
    """Paper default — L2 archived evidence (L3–L5 available via has_l3/l4/l5_evidence)."""
    del target_id, evidence_root
    return has_l2_archived_evidence(item, repo_root=repo_root)


def classify_execution_item(item: dict) -> str:
    if operator_excluded(item):
        return "operator_excluded"
    status = str(item.get("status") or "")
    if status in ORCHESTRATION_SKIP_STATUSES:
        return "not_executed"
    if status in {"failed", "error"}:
        return "failed"
    if status in {"blocked", "authorization_denied", "skipped"}:
        return "operator_excluded"
    return "completed"


def all_execution_items(report: dict) -> list[dict]:
    """Merge execution_archive rounds with the final execution block."""
    structured = report.get("structured") or {}
    items: list[dict] = []
    for round_data in structured.get("execution_archive") or []:
        if isinstance(round_data, dict):
            items.extend(round_data.get("items") or [])
    items.extend((structured.get("execution") or {}).get("items") or [])
    return items


def execution_sets(
    execution: list[dict],
    poc_id,
    *,
    target_id: str = "",
    evidence_root: Path | None = None,
    repo_root: Path | None = None,
    dedupe_by_poc: bool = False,
) -> dict[str, set[str]]:
    if not dedupe_by_poc:
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
            if bucket == "not_executed":
                continue
            started.add(pid)
            if bucket == "completed":
                completed.add(pid)
                if has_l2_archived_evidence(item, repo_root=repo_root):
                    evidence.add(pid)
        return {
            "started": started,
            "completed": completed,
            "evidence": evidence,
            "auditable": evidence,
            "operator_skipped": operator_skipped,
        }

    grouped: dict[str, list[dict]] = {}
    for item in execution:
        pid = poc_id(item)
        if pid:
            grouped.setdefault(pid, []).append(item)

    started = set()
    completed = set()
    evidence = set()
    l3 = set()
    l4 = set()
    l5 = set()
    operator_skipped = set()
    for pid, group in grouped.items():
        if all(operator_excluded(item) for item in group):
            operator_skipped.add(pid)
            continue
        has_l2 = any(has_l2_archived_evidence(item, repo_root=repo_root) for item in group)
        has_l3_item = any(
            has_l3_evidence(
                item,
                target_id=target_id,
                evidence_root=evidence_root,
                repo_root=repo_root,
            )
            for item in group
        )
        has_l4_item = any(
            has_l4_evidence(
                item,
                target_id=target_id,
                evidence_root=evidence_root,
                repo_root=repo_root,
            )
            for item in group
        )
        has_l5_item = any(
            has_l5_evidence(
                item,
                target_id=target_id,
                evidence_root=evidence_root,
                repo_root=repo_root,
            )
            for item in group
        )
        was_executed = has_l2 or has_l3_item or any(
            classify_execution_item(item) == "completed" for item in group
        )
        if not was_executed:
            continue
        started.add(pid)
        completed.add(pid)
        if has_l2:
            evidence.add(pid)
        if has_l3_item:
            l3.add(pid)
        if has_l4_item:
            l4.add(pid)
        if has_l5_item:
            l5.add(pid)
    return {
        "started": started,
        "completed": completed,
        "evidence": evidence,
        "l3": l3,
        "l4": l4,
        "l5": l5,
        "auditable": l5,
        "operator_skipped": operator_skipped,
    }


def evidence_rate_from_agent_report(
    report: dict,
    *,
    evidence_root: Path | None = None,
    repo_root: Path | None = None,
    poc_id=None,
    auditable: bool = True,
    evidence_level: str = "l5",
) -> tuple[int, int, float | None]:
    """Paper default uses L5 evidence; pass auditable=False for L2, or evidence_level=l3/l4."""
    target_id = str(report.get("target_id") or "")
    execution = all_execution_items(report)
    if poc_id is None:
        poc_id = lambda item: str(item.get("poc_name") or item.get("poc_file") or "")
    buckets = execution_sets(
        execution,
        poc_id,
        target_id=target_id,
        evidence_root=evidence_root,
        repo_root=repo_root,
        dedupe_by_poc=True,
    )
    completed = len(buckets["completed"])
    if not auditable:
        evidence_key = "evidence"
    else:
        evidence_key = str(evidence_level or "l5").strip().lower()
        if evidence_key not in {"l3", "l4", "l5", "auditable"}:
            evidence_key = "l5"
        if evidence_key == "auditable":
            evidence_key = "l5"
    archived = len(buckets[evidence_key] & buckets["completed"])
    rate = (archived / completed) if completed else None
    return archived, completed, rate

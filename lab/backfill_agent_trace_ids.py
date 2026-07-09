#!/usr/bin/env python3
"""Backfill missing branch_results.trace_id in archived agent run reports."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = ROOT / "lab" / "evidence"
DEFAULT_TRACE_ID = "agent_auto"


def _report_fallback_trace_id(report: dict) -> str:
    for finding in report.get("findings") or []:
        trace_id = str(finding.get("trace_id") or "").strip()
        if trace_id:
            return trace_id
    structured = report.get("structured") or {}
    for key in ("trace_id", "session_id"):
        trace_id = str(structured.get(key) or "").strip()
        if trace_id:
            return trace_id
    return DEFAULT_TRACE_ID


def backfill_report(report: dict) -> tuple[int, int]:
    fallback = _report_fallback_trace_id(report)
    patched_branches = 0
    patched_items = 0
    execution = (((report.get("structured") or {}).get("execution") or {}).get("items") or [])
    for item in execution:
        item_trace = str(item.get("trace_id") or "").strip() or fallback
        if not str(item.get("trace_id") or "").strip():
            item["trace_id"] = item_trace
            patched_items += 1
        for branch in item.get("branch_results") or []:
            if branch.get("success") is None:
                continue
            if str(branch.get("trace_id") or "").strip():
                continue
            branch["trace_id"] = item_trace
            patched_branches += 1
    return patched_branches, patched_items


def main() -> None:
    total_files = 0
    changed_files = 0
    total_branches = 0
    for path in sorted(EVIDENCE_ROOT.glob("**/agent_runs/*.json")):
        total_files += 1
        report = json.loads(path.read_text(encoding="utf-8"))
        patched_branches, patched_items = backfill_report(report)
        if not patched_branches and not patched_items:
            continue
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        changed_files += 1
        total_branches += patched_branches
        print(f"{path.relative_to(ROOT)}: branches={patched_branches} items={patched_items}")
    print(
        f"Done. files={total_files} changed={changed_files} "
        f"patched_branches={total_branches}"
    )


if __name__ == "__main__":
    main()

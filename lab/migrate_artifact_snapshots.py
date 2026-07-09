#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from artifacts import artifact_snapshot_path, snapshot_file_artifact


TRACKED_FILES = [
    "poc_coverage.json",
    "edge_capabilities.json",
    "resolved_scan_targets.json",
    "scan_results.json",
    "scan_baseline_summary.json",
    "agent_orchestration.json",
    "model_comparison.json",
    "comparison.json",
    "typical_cases.json",
    "summary.json",
    "target_summary.json",
]


def _mtime_run_id(path: Path) -> str:
    import time
    return time.strftime("%Y%m%d_%H%M%S", time.localtime(path.stat().st_mtime))


def _snapshot_if_missing(path: Path) -> Path | None:
    if not path.exists():
        return None
    run_id = _mtime_run_id(path)
    snapshot = artifact_snapshot_path(path, run_id)
    if snapshot.exists():
        return snapshot
    return snapshot_file_artifact(path, run_id)


def migrate_target_dir(target_dir: Path) -> dict:
    created = []
    for name in TRACKED_FILES:
        created_path = _snapshot_if_missing(target_dir / name)
        if created_path is not None:
            created.append(str(created_path))
        recovered = target_dir / name.replace(".json", ".recovered.json")
        created_path = _snapshot_if_missing(recovered)
        if created_path is not None:
            created.append(str(created_path))
    return {"target_dir": str(target_dir), "created": created}


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill timestamped artifact snapshots from existing experiment files.")
    parser.add_argument("--evidence-root", type=Path, default=Path("lab/evidence"))
    parser.add_argument("--target-id", action="append", default=[])
    args = parser.parse_args()

    target_ids = {item.strip() for item in args.target_id if item.strip()}
    results = []
    for path in sorted(args.evidence_root.iterdir()):
        if not path.is_dir():
            continue
        if target_ids and path.name not in target_ids:
            continue
        results.append(migrate_target_dir(path))

    import json
    print(json.dumps({"targets": results}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

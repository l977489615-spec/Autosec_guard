#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any


RUN_ID_PATTERN = re.compile(r"^(?P<stem>.+)__?(?P<run_id>\d{8}_\d{6})(?P<suffix>\.[^.]+)$")


def artifact_snapshot_path(path: Path, run_id: str) -> Path:
    return path.with_name(f"{path.stem}__{run_id}{path.suffix}")


def snapshot_json_artifact(path: Path, payload: Any, run_id: str) -> Path:
    snapshot = artifact_snapshot_path(path, run_id)
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    snapshot.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return snapshot


def snapshot_file_artifact(path: Path, run_id: str) -> Path | None:
    if not path.exists():
        return None
    snapshot = artifact_snapshot_path(path, run_id)
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, snapshot)
    return snapshot


def parse_run_id_from_path(path: Path) -> str:
    match = RUN_ID_PATTERN.match(path.name)
    return match.group("run_id") if match else ""


def list_artifact_snapshots(directory: Path, base_name: str) -> list[Path]:
    base = Path(base_name)
    patterns = [
        f"{base.stem}__*{base.suffix}",
        f"{base.stem}.recovered__*{base.suffix}",
    ]
    candidates = []
    for pattern in patterns:
        candidates.extend(path for path in directory.glob(pattern) if parse_run_id_from_path(path))
    return sorted(
        set(candidates),
        key=lambda item: (parse_run_id_from_path(item), item.name),
    )


def load_latest_json_artifact(directory: Path, base_name: str, default: Any):
    base_path = directory / base_name
    snapshots = list_artifact_snapshots(directory, base_name)
    if snapshots:
        return json.loads(snapshots[-1].read_text(encoding="utf-8"))
    if base_path.exists():
        return json.loads(base_path.read_text(encoding="utf-8"))
    return default


def load_versioned_json_rows(directory: Path, base_name: str, *, payload_key: str | None = None) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    snapshots = list_artifact_snapshots(directory, base_name)
    if not snapshots:
        legacy_path = directory / base_name
        if legacy_path.exists():
            data = json.loads(legacy_path.read_text(encoding="utf-8"))
            if payload_key and isinstance(data, dict):
                values = data.get(payload_key) or []
            else:
                values = data
            if isinstance(values, list):
                for item in values:
                    if isinstance(item, dict):
                        rows.append(dict(item))
        return rows

    for snapshot in snapshots:
        data = json.loads(snapshot.read_text(encoding="utf-8"))
        run_id = parse_run_id_from_path(snapshot)
        values = data.get(payload_key) if payload_key and isinstance(data, dict) else data
        if not isinstance(values, list):
            continue
        for item in values:
            if isinstance(item, dict):
                row = dict(item)
                row.setdefault("artifact_run_id", run_id)
                row.setdefault("artifact_file", str(snapshot))
                dedupe_key = json.dumps({k: v for k, v in row.items() if k not in {"artifact_run_id", "artifact_file"}}, sort_keys=True, ensure_ascii=False)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                rows.append(row)
    return rows

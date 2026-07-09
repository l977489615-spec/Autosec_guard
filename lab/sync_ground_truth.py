#!/usr/bin/env python3
"""将 Global scan_results 与 template 合并，写入 lab/ground_truth/<TARGET>.json。"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def read_json(path: Path, default=None):
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sync_ground_truth(target_id: str, scan_rows: list[dict], gt_dir: Path) -> dict:
    template = read_json(gt_dir / f"{target_id}.template.json", {}) or {}
    template_pos = set(template.get("positive_pocs") or [])
    scan_pos = {
        row.get("poc_file")
        for row in scan_rows
        if row.get("vulnerable") is True and row.get("status") == "completed" and row.get("poc_file")
    }
    if template_pos:
        positives = sorted(template_pos | scan_pos)
    else:
        positives = sorted(scan_pos)
    payload = {
        "target_id": target_id,
        "description": template.get("description") or f"{target_id} ground truth",
        "positive_pocs": positives,
        "negative_pocs": sorted(template.get("negative_pocs") or []),
        "notes": template.get("notes") or "由 template + Global 扫描合并生成",
        "scan_confirmed_count": len(scan_pos),
    }
    write_json(gt_dir / f"{target_id}.json", payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--scan-results", type=Path, required=True)
    parser.add_argument("--gt-dir", type=Path, default=Path("lab/ground_truth"))
    args = parser.parse_args()
    rows = read_json(args.scan_results, []) or []
    payload = sync_ground_truth(args.target_id, rows, args.gt_dir)
    print(json.dumps({"target_id": args.target_id, "positive_count": len(payload.get("positive_pocs") or [])}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

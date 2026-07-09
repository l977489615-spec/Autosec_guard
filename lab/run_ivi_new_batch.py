#!/usr/bin/env python3
"""批量运行已归类的 IVI 原厂 PoC，结果写入 lab/evidence。"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IVI_POC_DIR = ROOT / "server" / "pocs" / "application"
RUNNER = IVI_POC_DIR / "run_experiment.py"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run selected IVI new PoCs for lab evidence.")
    parser.add_argument("--output-dir", type=Path, default=Path("lab/evidence"))
    parser.add_argument(
        "--poc",
        action="append",
        default=None,
        help="poc stem 或文件名，可重复",
    )
    parser.add_argument("--serial", default="", help="ADB serial，传给 --serial")
    args = parser.parse_args()

    if not RUNNER.is_file():
        print(f"missing runner: {RUNNER}", file=sys.stderr)
        return 1

    args.output_dir.mkdir(parents=True, exist_ok=True)
    out_json = args.output_dir / "ivi_new_poc_results.json"
    cmd = [sys.executable, str(RUNNER), "--json", str(out_json)]
    selected_pocs = args.poc or [
        "poc10_http",
        "poc11_debuggable",
        "poc12_allowbackup",
        "poc17_provider_export",
    ]
    for poc in selected_pocs:
        cmd.extend(["--poc", poc])
    if args.serial:
        cmd.extend(["--serial", args.serial])

    print("Running:", " ".join(cmd))
    proc = subprocess.run(cmd, cwd=str(IVI_POC_DIR), capture_output=True, text=True)
    print(proc.stdout)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        return proc.returncode

    if out_json.is_file():
        rows = json.loads(out_json.read_text(encoding="utf-8"))
        summary = {
            "total": len(rows),
            "vulnerable": sum(1 for row in rows if row.get("vulnerable") is True),
            "errors": sum(1 for row in rows if row.get("status") == "error"),
            "output_file": str(out_json),
        }
        (args.output_dir / "ivi_new_poc_summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""IVI 原厂应用类 PoC 实验统一入口（遗留批处理，不接入主扫描引擎）。"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from _experiment.runner import discover_pocs, run_batch, run_poc  # noqa: E402


def _print_table(results):
    for item in results:
        flag = "?"
        if item.vulnerable is True:
            flag = "VULN"
        elif item.vulnerable is False:
            flag = "OK"
        print(f"[{item.status:7}] {flag:4} {item.poc_id:28} {item.duration_ms:5}ms  {item.title[:60]}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run IVI lab PoCs under server/pocs/application")
    parser.add_argument("--list", action="store_true", help="列出可用 PoC")
    parser.add_argument("--all", action="store_true", help="顺序执行全部自动化 PoC")
    parser.add_argument("--poc", action="append", default=[], help="指定 poc 文件名或 stem，可重复")
    parser.add_argument("--serial", help="传递给 PoC 的 ADB serial（--serial 参数）")
    parser.add_argument("--json", dest="json_out", help="将结果写入 JSON 文件")
    parser.add_argument("--include-manual", action="store_true", help="列表中包含 CAN 人工用例")
    args = parser.parse_args()

    if args.list:
        for item in discover_pocs(include_manual=args.include_manual):
            kind = "manual" if item.get("manual") else "auto"
            print(f"{item['poc_id']:28} [{kind:6}] {item.get('category','?'):16} {item.get('title','')[:70]}")
        return 0

    argv = ["--serial", args.serial] if args.serial else None
    if args.all:
        results = run_batch(workdir=ROOT)
    elif args.poc:
        results = [run_poc(name, argv=argv, workdir=ROOT) for name in args.poc]
    else:
        parser.print_help()
        return 1

    _print_table(results)
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps([item.to_dict() for item in results], ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    return 1 if any(item.status == "error" for item in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())

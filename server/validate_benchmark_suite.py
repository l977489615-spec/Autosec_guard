#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

from benchmark_suite import load_benchmark_suite, validate_benchmark_suite


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate benchmark suite schema and invariants.")
    parser.add_argument("--suite-file", type=Path, default=Path("benchmarks/default_suite.json"))
    args = parser.parse_args()

    suite = load_benchmark_suite(args.suite_file)
    report = validate_benchmark_suite(suite)
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    print(rendered)
    return 0 if report.get("valid") else 1


if __name__ == "__main__":
    raise SystemExit(main())

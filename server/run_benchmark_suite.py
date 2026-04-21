#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

from benchmark_suite import load_benchmark_suite, score_benchmark_suite, validate_benchmark_suite


def _load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _select_benchmarks_for_session(suite: dict, session_payload: dict, session_file: Path) -> tuple[list[dict], list[str]]:
    selected_ids = session_payload.get("benchmark_ids") or []
    if not selected_ids and session_payload.get("benchmark_id"):
        selected_ids = [session_payload.get("benchmark_id")]

    benchmarks = suite.get("benchmarks", []) or []
    if selected_ids:
        selected = [benchmark for benchmark in benchmarks if benchmark.get("id") in set(selected_ids)]
        if selected:
            return selected, selected_ids

    session_id = session_payload.get("session_id")
    fixture_hint = str(session_file).replace("\\", "/")
    selected = [
        benchmark
        for benchmark in benchmarks
        if benchmark.get("fixture_file") == fixture_hint
        or benchmark.get("fixture_file", "").endswith(session_file.name)
        or benchmark.get("id") == session_id
    ]
    return selected, selected_ids


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the AutoSec benchmark regression suite.")
    parser.add_argument("--session-file", type=Path, help="Path to a saved session JSON payload.")
    parser.add_argument("--fixture-dir", type=Path, help="Directory containing session fixture JSON payloads.")
    parser.add_argument("--suite-file", type=Path, help="Path to a benchmark suite JSON file.")
    parser.add_argument("--min-pass-rate", type=float, default=1.0, help="Minimum acceptable pass rate across benchmarks.")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero if any benchmark fails.")
    parser.add_argument("--output-file", type=Path, help="Optional path to write the JSON report.")
    args = parser.parse_args()

    server_dir = Path(__file__).resolve().parent
    suite = load_benchmark_suite(args.suite_file) if args.suite_file else load_benchmark_suite()
    validation = validate_benchmark_suite(suite)
    if not validation.get("valid"):
        rendered = json.dumps({"suite_validation": validation}, ensure_ascii=False, indent=2)
        print(rendered)
        return 1
    fixture_dir = args.fixture_dir or (server_dir / "benchmarks" / "fixtures")
    session_files = []
    if args.session_file:
        session_files = [args.session_file]
    elif fixture_dir.exists() and fixture_dir.is_dir():
        session_files = sorted(p for p in fixture_dir.glob("*.json") if p.is_file())
    else:
        session_files = [server_dir / "benchmarks" / "sample_session.json"]

    exit_code = 0
    run_results = []
    failing_benchmark_ids = []
    failing_runs = []
    for session_file in session_files:
        session_payload = _load_json(session_file)
        run_suite = suite
        selected, selected_ids = _select_benchmarks_for_session(suite, session_payload, session_file)
        if selected:
            run_suite = dict(suite)
            run_suite["benchmarks"] = selected
        result = score_benchmark_suite(session_payload, run_suite)
        result["session_file"] = str(session_file)
        result["suite_file"] = str(args.suite_file) if args.suite_file else str(server_dir / "benchmarks" / "default_suite.json")
        pass_rate = (result["passed_count"] / result["benchmark_count"]) if result["benchmark_count"] else 0.0
        result["pass_rate"] = round(pass_rate, 3)
        result["passed"] = bool(result["benchmark_count"]) and result["passed_count"] == result["benchmark_count"] and pass_rate >= args.min_pass_rate
        if not result["benchmark_count"]:
            result["selection_error"] = "No benchmark matched this session."
        run_results.append(result)
        if result["passed_count"] < result["benchmark_count"]:
            failing_benchmark_ids.extend(
                score["benchmark_id"]
                for score in result.get("scores", [])
                if not score.get("passed")
            )
        if not result["passed"]:
            failing_runs.append(str(session_file))
        if args.strict and not result["passed"]:
            exit_code = 1

    total_benchmarks = sum(run["benchmark_count"] for run in run_results)
    total_passed = sum(run["passed_count"] for run in run_results)
    overall_pass_rate = round((total_passed / total_benchmarks), 3) if total_benchmarks else 0.0
    passed = bool(total_benchmarks) and overall_pass_rate >= args.min_pass_rate and total_passed == total_benchmarks
    gate = {
        "min_pass_rate": args.min_pass_rate,
        "overall_pass_rate": overall_pass_rate,
        "passed": passed,
        "passed_run_count": sum(1 for run in run_results if run.get("passed")),
        "failed_run_count": sum(1 for run in run_results if not run.get("passed")),
        "failed_runs": failing_runs,
        "failing_benchmark_ids": sorted(set(failing_benchmark_ids)),
    }

    output = {
        "suite_scope": "fixture-dir" if len(session_files) > 1 else "single-session",
        "summary": {
            "session_count": len(run_results),
            "benchmark_count": total_benchmarks,
            "passed_count": total_passed,
            "failed_count": total_benchmarks - total_passed,
            "pass_rate": overall_pass_rate,
            "threshold": args.min_pass_rate,
            "strict": args.strict,
        },
        "runs": run_results,
        "run_count": len(run_results),
        "gate": gate,
        "report": (
            f"Regression gate: pass_rate={overall_pass_rate:.3f}, "
            f"threshold={args.min_pass_rate:.3f}, "
            f"passed={str(passed).lower()}, "
            f"failing={','.join(gate['failing_benchmark_ids']) or 'none'}"
        ),
    }
    rendered = json.dumps(output, ensure_ascii=False, indent=2)
    print(rendered)
    if args.output_file:
        args.output_file.parent.mkdir(parents=True, exist_ok=True)
        args.output_file.write_text(rendered + "\n", encoding="utf-8")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

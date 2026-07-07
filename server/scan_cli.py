#!/usr/bin/env python3
"""Command-line scanner for AutoSec Guard.

Modes:
  single  - run one PoC and print the result to stdout
  global  - run many PoCs and write JSON/Markdown reports
  agent   - call the existing agent-scan API and write JSON/Markdown reports
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from poc_catalog import list_available_poc_names, resolve_poc_source
from poc_execution_service import normalize_poc_params
from poc_worker import _extract_security_profile, poc_requires_human_review


SERVER_DIR = Path(__file__).resolve().parent
POCS_DIR = SERVER_DIR / "pocs"
SANDBOX_RUNNER = SERVER_DIR / "sandbox_runner.py"
REPORTS_DIR = SERVER_DIR / "reports"


def _now_id() -> str:
    return _dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def _parse_param_items(items: list[str]) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for item in items or []:
        if "=" not in item:
            raise SystemExit(f"Invalid --param {item!r}; expected key=value")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise SystemExit(f"Invalid --param {item!r}; key is empty")
        params[key] = _coerce_scalar(value)
    return params


def _coerce_scalar(value: str) -> Any:
    value = value.strip()
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.lower() in {"null", "none"}:
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def _load_params(args: argparse.Namespace) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if getattr(args, "params_json", ""):
        params.update(json.loads(args.params_json))
    if getattr(args, "params_file", ""):
        params.update(json.loads(Path(args.params_file).read_text(encoding="utf-8")))
    params.update(_parse_param_items(getattr(args, "param", []) or []))

    if getattr(args, "target_ip", ""):
        params["target_ip"] = args.target_ip
    if getattr(args, "target_port", None) is not None:
        params["target_port"] = args.target_port
    if getattr(args, "candidate_ports", ""):
        params["candidate_ports"] = args.candidate_ports
    if getattr(args, "bluetooth_mac", ""):
        params["bluetooth_mac"] = args.bluetooth_mac
    if getattr(args, "can_interface", ""):
        params["can_interface"] = args.can_interface
    return normalize_poc_params(params)


def _extract_result(stdout: str) -> dict[str, Any]:
    token = "===RESULT_TOKEN==="
    if token not in stdout:
        return {"success": False, "error": "sandbox result token missing", "raw_output": stdout}
    raw = stdout.split(token, 1)[-1].strip().splitlines()[0]
    data = json.loads(raw)
    if "error" in data:
        data["success"] = False
    else:
        data["success"] = True
    return data


def run_single_poc(poc_name: str, params: dict[str, Any], timeout: int = 60) -> dict[str, Any]:
    poc_path, normalized, poc_code = resolve_poc_source(str(POCS_DIR), poc_name)
    if not poc_path or not normalized:
        raise FileNotFoundError(f"PoC not found: {poc_name}")

    env = os.environ.copy()
    if poc_code and not Path(poc_path).exists():
        import base64

        env["AUTOSEC_POC_INLINE_CODE_B64"] = base64.b64encode(poc_code.encode("utf-8")).decode("ascii")
        env["AUTOSEC_POC_INLINE_NAME"] = normalized

    started = time.time()
    proc = subprocess.run(
        [sys.executable, str(SANDBOX_RUNNER), str(poc_path), json.dumps(params, ensure_ascii=False)],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )
    result = _extract_result((proc.stdout or "") + (proc.stderr or ""))
    result.update({
        "poc_id": normalized,
        "returncode": proc.returncode,
        "elapsed_seconds": round(time.time() - started, 3),
    })
    return result


def _format_single_result(result: dict[str, Any]) -> str:
    status = "ERROR" if not result.get("success") else ("VULNERABLE" if result.get("vulnerable") else "NOT VULNERABLE")
    lines = [
        f"PoC: {result.get('poc_id', '')}",
        f"Status: {status}",
        f"CVE: {result.get('cve_id') or 'N/A'}",
        f"Elapsed: {result.get('elapsed_seconds', 0)}s",
    ]
    if result.get("error"):
        lines.append(f"Error: {result['error']}")
    evidence = result.get("evidence")
    if evidence:
        lines.append("Evidence:")
        lines.append(str(evidence))
    return "\n".join(lines)


def _should_skip_poc(rel_path: str, include_manual: bool, include_disruptive: bool) -> tuple[bool, str]:
    poc_path, normalized, poc_code = resolve_poc_source(str(POCS_DIR), rel_path)
    if not poc_path or not normalized:
        return True, "not_found"
    try:
        profile = _extract_security_profile(poc_path, poc_code=poc_code if not Path(poc_path).exists() else None)
    except Exception as exc:
        return True, f"profile_error:{exc}"
    if not include_disruptive and bool(profile.get("is_disruptive")):
        return True, "disruptive_skipped"
    if not include_manual and poc_requires_human_review(normalized, profile):
        return True, "manual_review_skipped"
    return False, ""


def _select_pocs(category: str = "", pattern: str = "", limit: int = 0, include_manual: bool = False, include_disruptive: bool = False) -> list[str]:
    pocs = []
    for rel in list_available_poc_names(str(POCS_DIR)):
        if category and not rel.startswith(category.strip("/") + "/"):
            continue
        if pattern and pattern.lower() not in rel.lower():
            continue
        skip, _ = _should_skip_poc(rel, include_manual, include_disruptive)
        if skip:
            continue
        pocs.append(rel)
        if limit and len(pocs) >= limit:
            break
    return pocs


def run_global_scan(args: argparse.Namespace) -> dict[str, Any]:
    params = _load_params(args)
    pocs = _select_pocs(
        category=args.category,
        pattern=args.pattern,
        limit=args.limit,
        include_manual=args.include_manual,
        include_disruptive=args.include_disruptive,
    )
    session_id = args.session_id or f"cli-global-{_now_id()}"
    results = []
    started = time.time()
    for index, poc in enumerate(pocs, start=1):
        print(f"[{index}/{len(pocs)}] {poc}")
        try:
            item = run_single_poc(poc, params, timeout=args.timeout)
        except Exception as exc:
            item = {"success": False, "poc_id": poc, "error": str(exc), "vulnerable": False}
        results.append(item)

    report = {
        "mode": "global",
        "session_id": session_id,
        "target": {
            "target_ip": params.get("target_ip", ""),
            "target_port": params.get("target_port", ""),
            "candidate_ports": params.get("candidate_ports", ""),
        },
        "started_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "duration_seconds": round(time.time() - started, 3),
        "total": len(results),
        "vulnerable_count": sum(1 for r in results if r.get("vulnerable") is True),
        "error_count": sum(1 for r in results if not r.get("success")),
        "results": results,
    }
    _write_reports(report, args.output)
    return report


def run_agent_scan(args: argparse.Namespace) -> dict[str, Any]:
    params = _load_params(args)
    base_url = args.api_url.rstrip("/")
    payload = {
        "target_ip": params.get("target_ip"),
        "target_name": args.target_name,
        "can_interface": params.get("can_interface", ""),
        "bluetooth_mac": params.get("bluetooth_mac", ""),
        "wifi_interface": params.get("wifi_interface", ""),
        "context": args.context,
    }
    if args.ai_config_file:
        payload["ai_config"] = json.loads(Path(args.ai_config_file).read_text(encoding="utf-8"))
    headers = {"Content-Type": "application/json"}
    if args.token:
        headers["Authorization"] = args.token if args.token.startswith("Bearer ") else f"Bearer {args.token}"
    req = urllib.request.Request(
        f"{base_url}/api/agent-scan",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        data = {"error": body, "status": exc.code}
    report = {
        "mode": "agent",
        "session_id": args.session_id or f"cli-agent-{_now_id()}",
        "target": {"target_ip": params.get("target_ip", ""), "target_name": args.target_name},
        "started_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "duration_seconds": round(time.time() - started, 3),
        "agent_result": data,
    }
    _write_reports(report, args.output)
    return report


def _write_reports(report: dict[str, Any], output: str = "") -> tuple[Path, Path]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    base = Path(output) if output else REPORTS_DIR / f"{report.get('session_id') or _now_id()}_report"
    if base.suffix:
        base = base.with_suffix("")
    json_path = base.with_suffix(".json")
    md_path = base.with_suffix(".md")
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")
    return json_path, md_path


def _render_markdown(report: dict[str, Any]) -> str:
    mode = report.get("mode", "scan")
    lines = [
        f"# AutoSec Guard {mode.title()} Scan Report",
        "",
        f"- Session: `{report.get('session_id', '')}`",
        f"- Started: `{report.get('started_at', '')}`",
        f"- Duration: `{report.get('duration_seconds', 0)}s`",
        f"- Target: `{json.dumps(report.get('target', {}), ensure_ascii=False)}`",
        "",
    ]
    if mode == "global":
        lines.extend([
            "## Summary",
            "",
            f"- Total PoCs: `{report.get('total', 0)}`",
            f"- Vulnerable: `{report.get('vulnerable_count', 0)}`",
            f"- Errors: `{report.get('error_count', 0)}`",
            "",
            "## Findings",
            "",
        ])
        findings = [r for r in report.get("results", []) if r.get("vulnerable") is True]
        if not findings:
            lines.append("No vulnerable results were reported.")
        for item in findings:
            lines.extend([
                f"### {item.get('poc_id', '')}",
                "",
                f"- CVE: `{item.get('cve_id') or 'N/A'}`",
                f"- Elapsed: `{item.get('elapsed_seconds', 0)}s`",
                "",
                "```text",
                str(item.get("evidence") or ""),
                "```",
                "",
            ])
    else:
        lines.extend([
            "## Agent Result",
            "",
            "```json",
            json.dumps(report.get("agent_result", {}), ensure_ascii=False, indent=2),
            "```",
        ])
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AutoSec Guard command-line scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(scan: argparse.ArgumentParser) -> None:
        scan.add_argument("--target-ip", default="", help="Target IP address")
        scan.add_argument("--target-port", type=int, default=None, help="Target TCP/UDP port")
        scan.add_argument("--candidate-ports", default="", help="Comma-separated candidate ports")
        scan.add_argument("--bluetooth-mac", default="", help="Bluetooth MAC address")
        scan.add_argument("--can-interface", default="", help="CAN interface name")
        scan.add_argument("--params-json", default="", help="Inline JSON parameters")
        scan.add_argument("--params-file", default="", help="JSON parameter file")
        scan.add_argument("--param", action="append", default=[], help="Additional key=value parameter")
        scan.add_argument("--timeout", type=int, default=60, help="Timeout seconds")

    single = sub.add_parser("single", help="Run one PoC and print the result")
    single.add_argument("poc", help="PoC filename or relative path")
    add_common(single)

    global_scan = sub.add_parser("global", help="Run a batch/global scan and write reports")
    add_common(global_scan)
    global_scan.add_argument("--category", default="", help="Only scan a category, e.g. network")
    global_scan.add_argument("--pattern", default="", help="Only scan PoCs whose path contains this text")
    global_scan.add_argument("--limit", type=int, default=0, help="Limit number of PoCs")
    global_scan.add_argument("--include-manual", action="store_true", help="Include PoCs requiring manual review")
    global_scan.add_argument("--include-disruptive", action="store_true", help="Include disruptive PoCs")
    global_scan.add_argument("--session-id", default="", help="Report session id")
    global_scan.add_argument("--output", default="", help="Output path prefix for reports")

    agent = sub.add_parser("agent", help="Run agent scan through the existing API and write reports")
    add_common(agent)
    agent.add_argument("--api-url", default="http://127.0.0.1:5001", help="AutoSec API base URL")
    agent.add_argument("--token", default=os.environ.get("AUTOSEC_TOKEN", ""), help="Bearer token or raw JWT")
    agent.add_argument("--target-name", default="CLI Target", help="Target display name")
    agent.add_argument("--context", default="", help="Additional agent context")
    agent.add_argument("--ai-config-file", default="", help="JSON AI config file")
    agent.add_argument("--session-id", default="", help="Report session id")
    agent.add_argument("--output", default="", help="Output path prefix for reports")
    agent.set_defaults(timeout=1800)

    list_cmd = sub.add_parser("list", help="List available PoCs")
    list_cmd.add_argument("--category", default="", help="Only list a category")
    list_cmd.add_argument("--pattern", default="", help="Only list matching paths")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "single":
        result = run_single_poc(args.poc, _load_params(args), timeout=args.timeout)
        print(_format_single_result(result))
        return 1 if not result.get("success") else 0
    if args.command == "global":
        report = run_global_scan(args)
        return 1 if report.get("error_count") else 0
    if args.command == "agent":
        report = run_agent_scan(args)
        agent_result = report.get("agent_result", {})
        return 1 if agent_result.get("error") else 0
    if args.command == "list":
        for poc in _select_pocs(category=args.category, pattern=args.pattern):
            print(poc)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

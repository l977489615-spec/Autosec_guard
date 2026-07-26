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
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from poc_catalog import list_available_poc_names, resolve_poc_source
from poc_execution_service import normalize_poc_params
from poc_worker import _extract_security_profile, poc_requires_human_review
from audit_exp_readiness import PROFESSIONAL_TIER_ORDER, audit_all, audit_file, write_reports as write_exp_reports


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
    vuln = result.get("vulnerable")
    if not result.get("success"):
        status = "ERROR"
    elif vuln is True:
        status = "VULNERABLE"
    elif vuln is False:
        status = "NOT VULNERABLE"
    else:
        status = "INCONCLUSIVE"

    lines = [
        f"PoC: {result.get('poc_id', '')}",
        f"Status: {status}",
        f"CVE: {result.get('cve_id') or 'N/A'}",
        f"Elapsed: {result.get('elapsed_seconds', 0)}s",
    ]

    # Detection confidence — show when present
    dc = result.get("detection_confidence")
    if dc:
        if isinstance(dc, str):
            import json as _j
            try: dc = _j.loads(dc)
            except Exception: dc = {}
        if isinstance(dc, dict):
            level = dc.get("level", "?")
            conf  = dc.get("confidence", "?")
            fpr   = dc.get("fp_risk", "?")
            meth  = dc.get("method", "?")
            lines.append(f"Detection: Level={level} confidence={conf} fp_risk={fpr} method={meth}")

    if result.get("error"):
        lines.append(f"Error: {result['error']}")
    if result.get("requires_manual_review"):
        lines.append("Note: Requires manual review for confirmation")
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


def _is_exp_ready_poc(rel_path: str) -> bool:
    poc_path, normalized, _ = resolve_poc_source(str(POCS_DIR), rel_path)
    if not poc_path or not normalized:
        return False
    path = Path(poc_path)
    if not path.exists():
        return False
    finding = audit_file(path)
    return bool(finding and finding.grade == "EXP_READY")


def _is_scanner_ready_poc(rel_path: str) -> bool:
    poc_path, normalized, _ = resolve_poc_source(str(POCS_DIR), rel_path)
    if not poc_path or not normalized:
        return False
    path = Path(poc_path)
    if not path.exists():
        return False
    finding = audit_file(path)
    return bool(finding and (finding.scanner_ready or finding.grade in {"EXP_READY", "SCANNER_READY"}))


def _is_active_ready_poc(rel_path: str) -> bool:
    poc_path, normalized, _ = resolve_poc_source(str(POCS_DIR), rel_path)
    if not poc_path or not normalized:
        return False
    path = Path(poc_path)
    if not path.exists():
        return False
    finding = audit_file(path)
    return bool(finding and not finding.is_recon and finding.active_ready)


def _is_product_ready_poc(rel_path: str) -> bool:
    poc_path, normalized, _ = resolve_poc_source(str(POCS_DIR), rel_path)
    if not poc_path or not normalized:
        return False
    path = Path(poc_path)
    if not path.exists():
        return False
    finding = audit_file(path)
    return bool(finding and not finding.is_recon and getattr(finding, "product_ready", False))


def _professional_finding(rel_path: str):
    poc_path, normalized, _ = resolve_poc_source(str(POCS_DIR), rel_path)
    if not poc_path or not normalized:
        return None
    path = Path(poc_path)
    if not path.exists():
        return None
    return audit_file(path)


def _tier_allowed(
    tier: str,
    min_tier: str = "",
    max_tier: str = "",
) -> bool:
    tier = (tier or "PASSIVE").upper()
    min_tier = (min_tier or "").upper()
    max_tier = (max_tier or "").upper()
    value = PROFESSIONAL_TIER_ORDER.get(tier, PROFESSIONAL_TIER_ORDER["PASSIVE"])
    if min_tier and value < PROFESSIONAL_TIER_ORDER.get(min_tier, 0):
        return False
    if max_tier and value > PROFESSIONAL_TIER_ORDER.get(max_tier, max(PROFESSIONAL_TIER_ORDER.values())):
        return False
    return True


def _select_pocs(
    category: str = "",
    pattern: str = "",
    limit: int = 0,
    include_manual: bool = False,
    include_disruptive: bool = False,
    require_exp: bool = False,
    require_scanner: bool = False,
    require_active: bool = False,
    require_product: bool = False,
    min_tier: str = "",
    max_tier: str = "",
) -> list[str]:
    pocs = []
    for rel in list_available_poc_names(str(POCS_DIR)):
        if category and not rel.startswith(category.strip("/") + "/"):
            continue
        if pattern and pattern.lower() not in rel.lower():
            continue
        skip, _ = _should_skip_poc(rel, include_manual, include_disruptive)
        if skip:
            continue
        if require_exp and not _is_exp_ready_poc(rel):
            continue
        if require_scanner and not _is_scanner_ready_poc(rel):
            continue
        if require_active and not _is_active_ready_poc(rel):
            continue
        if require_product and not _is_product_ready_poc(rel):
            continue
        if min_tier or max_tier:
            finding = _professional_finding(rel)
            if not finding or not _tier_allowed(
                finding.validation_tier,
                min_tier,
                max_tier,
            ):
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
        require_exp=getattr(args, "require_exp", False),
        require_scanner=getattr(args, "require_scanner", False),
        require_active=getattr(args, "require_active", False),
        require_product=getattr(args, "require_product", False),
        min_tier=getattr(args, "min_tier", ""),
        max_tier=getattr(args, "max_tier", "ACTIVE_PROBE"),
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
        "inconclusive_count": sum(1 for r in results if r.get("vulnerable") is None and r.get("success")),
        "error_count": sum(1 for r in results if not r.get("success")),
        "detection_quality_summary": _detection_quality_summary(results),
        "results": results,
    }
    _write_reports(report, args.output)
    return report


def run_agent_scan(args: argparse.Namespace) -> dict[str, Any]:
    params = _load_params(args)
    base_url = args.api_url.rstrip("/")
    parsed_api = urllib.parse.urlparse(base_url)
    if parsed_api.scheme not in {"http", "https"} or not parsed_api.hostname:
        raise ValueError("--api-url must be an http(s) URL with a hostname")
    payload = {
        "target_ip": params.get("target_ip"),
        "target_name": args.target_name,
        "can_interface": params.get("can_interface", ""),
        "bluetooth_mac": params.get("bluetooth_mac", ""),
        "wifi_interface": params.get("wifi_interface", ""),
        "context": args.context,
        "approve_high_risk_batch": bool(getattr(args, "approve_high_risk_batch", False)),
        "execution_mode": getattr(args, "execution_mode", "progressive_auto"),
        "destructive_policy": (
            "allow_all"
            if bool(getattr(args, "approve_high_risk_batch", False))
            else getattr(args, "destructive_policy", "confirm_each")
        ),
        "risk_ceiling": getattr(args, "risk_ceiling", ""),
        "enable_reflection_reentry": bool(getattr(args, "enable_reflection_reentry", False)),
        "enable_weaponize": bool(getattr(args, "enable_weaponize", True)),
        "allow_domains": getattr(args, "allow_domains", []) or [],
        "lab_policy": bool(getattr(args, "lab_policy", False)),
    }
    if args.ai_config_file:
        payload["ai_config"] = json.loads(Path(args.ai_config_file).read_text(encoding="utf-8"))
    headers = {"Content-Type": "application/json"}
    if args.token:
        headers["Authorization"] = args.token if args.token.startswith("Bearer ") else f"Bearer {args.token}"
    req = urllib.request.Request(
        f"{base_url}/api/v1/agent-scan",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    started = time.time()
    try:
        # URL scheme and hostname were validated above.
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:  # nosec B310
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
        "enable_reflection_reentry": bool(getattr(args, "enable_reflection_reentry", False)),
        "agent_result": data,
    }
    _write_reports(report, args.output)
    return report


def _detection_quality_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate detection_confidence levels from a result list."""
    import json as _j
    levels: dict[str, int] = {"A": 0, "B": 0, "C": 0, "D": 0, "E": 0, "HW": 0, "unknown": 0}
    for r in results:
        dc = r.get("detection_confidence")
        if not dc:
            levels["unknown"] += 1
            continue
        if isinstance(dc, str):
            try: dc = _j.loads(dc)
            except Exception: levels["unknown"] += 1; continue
        if isinstance(dc, dict):
            levels[dc.get("level", "unknown")] = levels.get(dc.get("level", "unknown"), 0) + 1
        else:
            levels["unknown"] += 1
    total = sum(levels.values())
    high_quality = levels["A"] + levels["B"]
    medium_quality = levels["C"] + levels["HW"]
    return {
        "by_level": levels,
        "high_quality_pct": round(100 * high_quality / total, 1) if total else 0,
        "medium_quality_pct": round(100 * medium_quality / total, 1) if total else 0,
        "behavioral_confirmed": levels["A"],
        "functional_probe": levels["B"],
        "version_config_probe": levels["C"],
        "hardware_required": levels["HW"],
        "passive_only": levels["D"] + levels["E"],
    }


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
            f"- Reflection Reentry: `{bool(report.get('enable_reflection_reentry', False))}`",
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
    single.add_argument("--require-exp", action="store_true", help="Refuse to run unless the PoC is EXP_READY")
    single.add_argument("--require-scanner", action="store_true", help="Refuse to run unless the PoC is at least SCANNER_READY")
    single.add_argument("--require-active", action="store_true", help="Refuse to run unless the PoC reaches ACTIVE_READY")
    single.add_argument("--require-product", action="store_true", help="Refuse to run unless the PoC reaches PRODUCT_READY")
    single.add_argument("--min-tier", default="", choices=list(PROFESSIONAL_TIER_ORDER), help="Minimum professional validation tier")
    single.add_argument("--max-tier", default="", choices=list(PROFESSIONAL_TIER_ORDER), help="Maximum professional validation tier")
    add_common(single)

    global_scan = sub.add_parser("global", help="Run a batch/global scan and write reports")
    add_common(global_scan)
    global_scan.add_argument("--category", default="", help="Only scan a category, e.g. network")
    global_scan.add_argument("--pattern", default="", help="Only scan PoCs whose path contains this text")
    global_scan.add_argument("--limit", type=int, default=0, help="Limit number of PoCs")
    global_scan.add_argument("--include-manual", action="store_true", help="Include PoCs requiring manual review")
    global_scan.add_argument("--include-disruptive", action="store_true", help="Include disruptive PoCs")
    global_scan.add_argument("--require-exp", action="store_true", help="Only run EXP_READY PoCs")
    global_scan.add_argument("--require-scanner", action="store_true", help="Only run SCANNER_READY or EXP_READY PoCs")
    global_scan.add_argument("--require-active", action="store_true", help="Only run ACTIVE_READY PoCs")
    global_scan.add_argument("--require-product", action="store_true", help="Only run PRODUCT_READY PoCs")
    global_scan.add_argument("--min-tier", default="", choices=list(PROFESSIONAL_TIER_ORDER), help="Minimum professional validation tier")
    global_scan.add_argument("--max-tier", default="", choices=list(PROFESSIONAL_TIER_ORDER), help="Maximum professional validation tier")
    global_scan.add_argument("--session-id", default="", help="Report session id")
    global_scan.add_argument("--output", default="", help="Output path prefix for reports")

    agent = sub.add_parser("agent", help="Run agent scan through the existing API and write reports")
    add_common(agent)
    agent.add_argument("--api-url", default="http://127.0.0.1:5001", help="AutoSec API base URL")
    agent.add_argument("--token", default=os.environ.get("AUTOSEC_TOKEN", ""), help="Scoped Bearer API token")
    agent.add_argument("--target-name", default="CLI Target", help="Target display name")
    agent.add_argument("--context", default="", help="Additional agent context")
    agent.add_argument("--approve-high-risk-batch", action="store_true", help="Deprecated alias for --destructive-policy allow_all")
    agent.add_argument("--execution-mode", choices=["safe_only", "progressive_auto", "full_auto_lab"], default="progressive_auto", help="Agent disruptive execution policy")
    agent.add_argument(
        "--destructive-policy",
        choices=["allow_all", "confirm_each", "deny_all"],
        default="confirm_each",
        help="Destructive PoC decision: allow all in authorized scope, leave each pending for approval, or deny all",
    )
    agent.add_argument("--risk-ceiling", choices=["SAFE", "PROBE", "RESTART", "DATALOSS", "BRICK"], default="", help="Upper risk ceiling for automatic high-risk execution")
    agent.add_argument("--enable-reflection-reentry", action="store_true", help="Enable Reflector audit and limited reentry loop")
    agent.add_argument("--enable-weaponize", dest="enable_weaponize", action="store_true", default=True, help="Enable constrained unknown-service probe generation (default)")
    agent.add_argument("--disable-weaponize", dest="enable_weaponize", action="store_false", help="Disable LLM probe generation and use the deterministic safe probe template")
    agent.add_argument("--allow-domain", dest="allow_domains", action="append", default=[], help="Authorized PoC domain for batch auto-approval")
    agent.add_argument("--lab-policy", action="store_true", help="Mark this run as trusted lab context for DataLoss-level checks")
    agent.add_argument("--ai-config-file", default="", help="JSON AI config file")
    agent.add_argument("--session-id", default="", help="Report session id")
    agent.add_argument("--output", default="", help="Output path prefix for reports")
    agent.set_defaults(timeout=1800)

    list_cmd = sub.add_parser("list", help="List available PoCs")
    list_cmd.add_argument("--category", default="", help="Only list a category")
    list_cmd.add_argument("--pattern", default="", help="Only list matching paths")
    list_cmd.add_argument("--require-exp", action="store_true", help="Only list EXP_READY PoCs")
    list_cmd.add_argument("--require-scanner", action="store_true", help="Only list SCANNER_READY or EXP_READY PoCs")
    list_cmd.add_argument("--require-active", action="store_true", help="Only list ACTIVE_READY PoCs")
    list_cmd.add_argument("--require-product", action="store_true", help="Only list PRODUCT_READY PoCs")
    list_cmd.add_argument("--min-tier", default="", choices=list(PROFESSIONAL_TIER_ORDER), help="Minimum professional validation tier")
    list_cmd.add_argument("--max-tier", default="", choices=list(PROFESSIONAL_TIER_ORDER), help="Maximum professional validation tier")
    list_cmd.add_argument("--include-manual", action="store_true", help="Include PoCs requiring manual review")
    list_cmd.add_argument("--include-disruptive", action="store_true", help="Include disruptive PoCs")

    exp_audit = sub.add_parser("exp-audit", help="Audit PoCs for exploit-level readiness")
    exp_audit.add_argument("--prefix", default=f"exp_readiness_{_now_id()}", help="Report filename prefix under server/reports")
    exp_audit.add_argument("--fail-on-non-exp", action="store_true", help="Exit non-zero when vulnerability PoCs are not EXP_READY")
    exp_audit.add_argument("--professional-audit", action="store_true", help="Print professional tier distribution")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "single":
        if getattr(args, "require_exp", False) and not _is_exp_ready_poc(args.poc):
            print(f"Refusing to run non-EXP PoC: {args.poc}")
            print("Run `python3 server/scan_cli.py exp-audit` for missing EXP readiness fields.")
            return 2
        if getattr(args, "require_scanner", False) and not _is_scanner_ready_poc(args.poc):
            print(f"Refusing to run non-SCANNER_READY PoC: {args.poc}")
            print("Run `python3 server/scan_cli.py exp-audit` for readiness classification.")
            return 2
        if getattr(args, "require_active", False) and not _is_active_ready_poc(args.poc):
            print(f"Refusing to run non-ACTIVE_READY PoC: {args.poc}")
            print("Run `python3 server/scan_cli.py exp-audit --professional-audit` for active-readiness classification.")
            return 2
        if getattr(args, "require_product", False) and not _is_product_ready_poc(args.poc):
            print(f"Refusing to run non-PRODUCT_READY PoC: {args.poc}")
            print("Run `python3 server/scan_cli.py exp-audit --professional-audit` for product-readiness classification.")
            return 2
        effective_max_tier = args.max_tier
        if getattr(args, "min_tier", "") or effective_max_tier:
            finding = _professional_finding(args.poc)
            if not finding or not _tier_allowed(
                finding.validation_tier,
                args.min_tier,
                effective_max_tier,
            ):
                tier = finding.validation_tier if finding else "unknown"
                print(f"Refusing to run PoC outside professional tier policy: {args.poc} tier={tier}")
                return 2
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
        for poc in _select_pocs(
            category=args.category,
            pattern=args.pattern,
            include_manual=args.include_manual,
            include_disruptive=args.include_disruptive,
            require_exp=args.require_exp,
            require_scanner=args.require_scanner,
            require_active=args.require_active,
            require_product=args.require_product,
            min_tier=args.min_tier,
            max_tier=args.max_tier,
        ):
            print(poc)
        return 0
    if args.command == "exp-audit":
        findings = audit_all()
        json_path, csv_path = write_exp_reports(findings, args.prefix)
        scanner_ready = [
            item for item in findings
            if not item.is_recon and (item.scanner_ready or item.grade in {"EXP_READY", "SCANNER_READY"})
        ]
        active_ready = [item for item in findings if not item.is_recon and item.active_ready]
        product_ready = [item for item in findings if not item.is_recon and getattr(item, "product_ready", False)]
        non_exp = [
            item for item in findings
            if not item.is_recon and item.grade != "EXP_READY"
        ]
        below_active = [item for item in findings if not item.is_recon and not item.active_ready]
        below_product = [item for item in findings if not item.is_recon and not getattr(item, "product_ready", False)]
        print(f"Audited {len(findings)} plugin files")
        print(f"JSON report: {json_path}")
        print(f"CSV report: {csv_path}")
        print(f"Scanner-ready vulnerability plugins: {len(scanner_ready)}")
        print(f"Active-ready vulnerability plugins: {len(active_ready)}")
        print(f"Product-ready vulnerability plugins: {len(product_ready)}")
        print(f"Non-EXP vulnerability plugins: {len(non_exp)}")
        print(f"Below active-ready threshold: {len(below_active)}")
        print(f"Below product-ready threshold: {len(below_product)}")
        if getattr(args, "professional_audit", False):
            tier_counts = {}
            capability_counts = {}
            active_grade_counts = {}
            product_grade_counts = {}
            for item in findings:
                tier_counts[item.validation_tier] = tier_counts.get(item.validation_tier, 0) + 1
                capability_counts[item.exp_capability] = capability_counts.get(item.exp_capability, 0) + 1
                active_grade_counts[item.active_grade] = active_grade_counts.get(item.active_grade, 0) + 1
                product_grade_counts[getattr(item, "product_grade", "")] = product_grade_counts.get(getattr(item, "product_grade", ""), 0) + 1
            print(f"Professional tiers: {tier_counts}")
            print(f"EXP capabilities: {capability_counts}")
            print(f"Active grades: {active_grade_counts}")
            print(f"Product grades: {product_grade_counts}")
        return 2 if args.fail_on_non_exp and non_exp else 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

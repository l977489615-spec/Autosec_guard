#!/usr/bin/env python3
"""生成 Global（无 Agent）vs Agent 对比数据，写入 comparison.json（论文表8）。"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from artifacts import snapshot_json_artifact

TABLE8_PRIMARY_METRIC_NOTE = (
    "主指标为 gt_recall（相对 lab/ground_truth/<TARGET>.json）。"
    "Agent 为定向验证：仅对侦察/Global 已检出攻击面执行少量 PoC，"
    "不与 Global 全量 recon 扫描比召回。"
    "agent_finding_recall_vs_global 仅作工程参考。"
)
TABLE8_FOOTNOTE = (
    "脚注：表8 主列请引用 gt_recall / paper_primary_recall；"
    "poc_reduction_percent 表示较 Global 少跑的 PoC 比例（效率）；"
    "agent_finding_recall_vs_global 以 Global 检出为分母，不代表真值，勿与 gt_recall 混用。"
)


def read_json(path: Path, default=None):
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _safe_float(value, default: float = 0.0) -> float:
    try:
        if value in {"", None}:
            return default
        return float(value)
    except Exception:
        return default


def _extract_gt_hits_from_scan(scan_rows: list[dict], gt_positive: set[str]) -> tuple[list[str], float | str]:
    global_hits = sorted({
        row.get("poc_file")
        for row in scan_rows
        if row.get("vulnerable") is True and row.get("poc_file") in gt_positive
    })
    recall = round(len(global_hits) / len(gt_positive), 3) if gt_positive else ""
    return global_hits, recall


def _normalize_poc_name(item: dict) -> str:
    return str(
        item.get("poc_file")
        or item.get("filename")
        or item.get("poc_id")
        or item.get("poc_name")
        or ""
    ).strip()


def _normalize_finding_poc_name(item: dict) -> str:
    return str(
        item.get("poc_file")
        or item.get("filename")
        or item.get("poc_id")
        or item.get("poc_name")
        or item.get("name")
        or ""
    ).strip()


RECON_ONLY_PATTERNS = (
    "Host_Discovery",
    "TCP_Port_Scan",
    "mDNS_Service_Discovery",
    "UPnP_SSDP_Discovery",
    "TBox_Port_Scan",
)


def _is_recon_only_poc(poc_name: str) -> bool:
    return any(pattern in poc_name for pattern in RECON_ONLY_PATTERNS)


def _extract_agent_execution_sets(report_path: str) -> tuple[set[str], set[str], set[str], set[str]]:
    path = Path(report_path)
    if not path.is_file():
        return set(), set(), set(), set()
    report = read_json(path, {})
    structured = report.get("structured") or {}
    execution = (structured.get("execution") or {}).get("items") or []
    executed: set[str] = set()
    successful: set[str] = set()
    execution_vulnerable: set[str] = set()
    claimed_vulnerable: set[str] = set()
    for item in execution:
        if not isinstance(item, dict):
            continue
        poc = _normalize_poc_name(item)
        if not poc:
            continue
        executed.add(poc)
        if str(item.get("status") or "") in {"completed", "vulnerable", "pending_manual_review", "manual_review_completed"}:
            successful.add(poc)
        if item.get("vulnerable") is True:
            execution_vulnerable.add(poc)
    for finding in report.get("findings") or []:
        if isinstance(finding, dict):
            poc = _normalize_finding_poc_name(finding)
            if poc:
                claimed_vulnerable.add(poc)
    return executed, successful, execution_vulnerable, claimed_vulnerable


def build_comparison(target_dir: Path, target_id: str) -> list[dict]:
    scan_rows = read_json(target_dir / "scan_results.json", []) or []
    model_cmp = read_json(target_dir / "model_comparison.json", {}) or {}
    existing_rows = read_json(target_dir / "comparison.json", []) or []
    gt = read_json(Path("lab/ground_truth") / f"{target_id}.json", None)
    if gt is None:
        gt = read_json(target_dir / "ground_truth_hint.json", {}) or {}

    gt_positive = set(gt.get("positive_pocs") or [])

    global_elapsed = round(sum(float(row.get("elapsed_seconds") or 0) for row in scan_rows), 3)
    global_applicable = len(scan_rows)
    global_completed = sum(1 for row in scan_rows if row.get("status") == "completed")
    global_vulnerable = sum(1 for row in scan_rows if row.get("vulnerable") is True)
    global_blocked = sum(1 for row in scan_rows if row.get("blocked"))
    global_errors = sum(1 for row in scan_rows if row.get("status") == "error")
    global_execution_coverage = round(global_completed / max(global_applicable, 1), 4) if global_applicable else ""

    global_vuln_pocs = {
        row.get("poc_file")
        for row in scan_rows
        if row.get("vulnerable") is True and row.get("poc_file")
    }
    global_recon_only_vuln_pocs = {poc for poc in global_vuln_pocs if _is_recon_only_poc(poc)}
    global_security_vuln_pocs = global_vuln_pocs - global_recon_only_vuln_pocs
    global_completed_pocs = {
        row.get("poc_file")
        for row in scan_rows
        if row.get("status") in {"completed", "pending_manual_review"} and row.get("poc_file")
    }
    global_gt_hits, global_gt_recall = _extract_gt_hits_from_scan(scan_rows, gt_positive)

    rows: list[dict] = []
    for variant in model_cmp.get("variants") or []:
        report_file = variant.get("report_file") or ""
        (
            agent_executed_pocs,
            agent_successful_pocs,
            agent_execution_vuln_pocs,
            agent_claimed_vuln_pocs,
        ) = _extract_agent_execution_sets(report_file)
        agent_vuln_pocs = agent_execution_vuln_pocs
        unexecuted_claimed_pocs = sorted(agent_claimed_vuln_pocs - agent_executed_pocs)
        claimed_overlap_with_global = sorted(global_vuln_pocs & agent_claimed_vuln_pocs) if agent_claimed_vuln_pocs else []
        executed = int(variant.get("executed_poc_count") or len(agent_executed_pocs))
        agent_elapsed = _safe_float(variant.get("elapsed_seconds") or 0)
        overlap_exec_pocs = sorted(global_completed_pocs & agent_executed_pocs)
        extra_exec_pocs = sorted(agent_executed_pocs - global_completed_pocs)
        missed_exec_pocs = sorted(global_completed_pocs - agent_executed_pocs)
        baseline_coverage = round(len(overlap_exec_pocs) / max(len(global_completed_pocs), 1), 4) if global_completed_pocs else ""
        extra_success_pocs = sorted(agent_successful_pocs - global_completed_pocs)

        overlap_with_global = sorted(global_vuln_pocs & agent_vuln_pocs) if agent_vuln_pocs else []
        agent_only_findings = sorted(agent_vuln_pocs - global_vuln_pocs) if agent_vuln_pocs else []
        global_only_findings = sorted(global_vuln_pocs - agent_vuln_pocs) if global_vuln_pocs else []
        finding_recall_vs_global = round(len(overlap_with_global) / max(len(global_vuln_pocs), 1), 4) if global_vuln_pocs else ""
        finding_precision_vs_global = round(len(overlap_with_global) / max(len(agent_vuln_pocs), 1), 4) if agent_vuln_pocs else ""
        security_overlap_with_global = sorted(global_security_vuln_pocs & agent_vuln_pocs) if agent_vuln_pocs else []
        security_recall_vs_global = (
            round(len(security_overlap_with_global) / max(len(global_security_vuln_pocs), 1), 4)
            if global_security_vuln_pocs else ""
        )
        claimed_recall_vs_global = (
            round(len(claimed_overlap_with_global) / max(len(global_vuln_pocs), 1), 4)
            if global_vuln_pocs else ""
        )
        gt_hits = sorted(gt_positive & agent_vuln_pocs) if gt_positive and agent_vuln_pocs else []
        recall = round(len(gt_hits) / len(gt_positive), 3) if gt_positive else ""
        finding_count = _safe_float(variant.get("finding_count"), 0)
        poc_reduction = round((1 - executed / max(global_completed, 1)) * 100, 1)
        paper_primary_recall = recall if gt_positive else finding_precision_vs_global
        agent_findings_per_executed = round(finding_count / max(executed, 1), 3) if executed else ""
        agent_efficiency_score = ""
        if paper_primary_recall not in {"", None} and poc_reduction not in {"", None}:
            try:
                agent_efficiency_score = round(float(paper_primary_recall) * (1 + float(poc_reduction) / 100), 3)
            except Exception:
                agent_efficiency_score = ""

        rows.append({
            "target_id": target_id,
            "comparison_type": "global_vs_agent",
            "variant_id": variant.get("variant_id"),
            "variant_label": variant.get("variant_label"),
            "global_elapsed_seconds": global_elapsed,
            "global_applicable_poc_count": global_applicable,
            "global_executed_poc_count": global_completed,
            "global_vulnerable_count": global_vulnerable,
            "global_security_vulnerable_count": len(global_security_vuln_pocs),
            "global_recon_only_vulnerable_count": len(global_recon_only_vuln_pocs),
            "global_recon_only_vulnerable_pocs": sorted(global_recon_only_vuln_pocs),
            "global_blocked_count": global_blocked,
            "global_error_count": global_errors,
            "global_execution_coverage_ratio": global_execution_coverage,
            "agent_elapsed_seconds": agent_elapsed,
            "agent_planned_poc_count": variant.get("planned_poc_count"),
            "agent_executed_poc_count": executed,
            "baseline_replay_poc_count": variant.get("baseline_replay_poc_count", ""),
            "agent_execution_coverage_vs_global": baseline_coverage,
            "agent_raw_execution_ratio_vs_global": variant.get("agent_execution_coverage_vs_global"),
            "baseline_overlap_count": len(overlap_exec_pocs),
            "baseline_overlap_pocs": overlap_exec_pocs,
            "baseline_missed_count": len(missed_exec_pocs),
            "baseline_missed_pocs": missed_exec_pocs,
            "agent_extra_execution_count": len(extra_exec_pocs),
            "agent_extra_execution_pocs": extra_exec_pocs,
            "agent_extra_success_count": len(extra_success_pocs),
            "agent_extra_success_pocs": extra_success_pocs,
            "agent_finding_count": variant.get("finding_count"),
            "agent_reflection_reentry_count": variant.get("reflection_reentry_count"),
            "agent_llm_call_count": variant.get("llm_call_count"),
            "agent_prompt_tokens": variant.get("prompt_tokens"),
            "agent_completion_tokens": variant.get("completion_tokens"),
            "agent_total_tokens": variant.get("total_tokens"),
            "agent_avg_llm_latency_ms": variant.get("avg_llm_latency_ms"),
            "agent_tokens_per_finding": variant.get("tokens_per_finding"),
            "poc_count_reduction": max(0, global_completed - executed),
            "poc_reduction_percent": round((1 - executed / max(global_completed, 1)) * 100, 1),
            "time_ratio_global_over_agent": round(global_elapsed / max(agent_elapsed, 0.001), 2),
            "finding_overlap_with_global": len(overlap_with_global),
            "finding_overlap_pocs": overlap_with_global,
            "agent_finding_recall_vs_global": finding_recall_vs_global,
            "agent_finding_precision_vs_global": finding_precision_vs_global,
            "security_finding_overlap_with_global": len(security_overlap_with_global),
            "security_finding_overlap_pocs": security_overlap_with_global,
            "agent_security_finding_recall_vs_global": security_recall_vs_global,
            "claimed_finding_count": len(agent_claimed_vuln_pocs),
            "claimed_finding_overlap_with_global": len(claimed_overlap_with_global),
            "claimed_finding_overlap_pocs": claimed_overlap_with_global,
            "claimed_finding_recall_vs_global": claimed_recall_vs_global,
            "unexecuted_claimed_finding_count": len(unexecuted_claimed_pocs),
            "unexecuted_claimed_finding_pocs": unexecuted_claimed_pocs,
            "agent_only_finding_count": len(agent_only_findings),
            "agent_only_finding_pocs": agent_only_findings,
            "agent_extra_finding_count": len([p for p in agent_only_findings if p in extra_exec_pocs]),
            "global_only_finding_count": len(global_only_findings),
            "global_only_finding_pocs": global_only_findings,
            "gt_positive_count": len(gt_positive),
            "global_gt_hit_count": len(global_gt_hits),
            "global_gt_recall": global_gt_recall,
            "gt_hit_count": len(gt_hits),
            "gt_recall": recall,
            "paper_primary_recall": paper_primary_recall,
            "agent_gt_recall": recall,
            "agent_findings_per_executed_poc": agent_findings_per_executed,
            "agent_efficiency_score": agent_efficiency_score,
            "agent_finding_recall_vs_global_note": "参考指标：以 Global 检出为分母，不代表真值",
            "table8_primary_metric": "gt_recall",
            "table8_footnote": TABLE8_FOOTNOTE,
            "metric_interpretation": TABLE8_PRIMARY_METRIC_NOTE,
            "same_conclusion_note": (
                f"【主指标】GT召回={recall or 'N/A'}（命中{len(gt_hits)}/{len(gt_positive) or 0}）；"
                f"Agent({variant.get('variant_id')})发现{int(finding_count)}项，定向执行{executed}项"
                f"（较Global减少{poc_reduction}%）；"
                f"【参考】相对Global漏洞重合{len(overlap_with_global)}/{global_vulnerable or 0}"
            ),
        })
    preserved_rows = [
        row for row in existing_rows
        if not (isinstance(row, dict) and row.get("comparison_type") == "global_vs_agent")
    ]
    return preserved_rows + rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Global vs Agent comparison for one target directory.")
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--target-id", default="")
    parser.add_argument("--run-id", default="")
    args = parser.parse_args()

    target_id = args.target_id or args.target_dir.name
    rows = build_comparison(args.target_dir, target_id)
    write_json(args.target_dir / "comparison.json", rows)
    if args.run_id:
        snapshot_json_artifact(args.target_dir / "comparison.json", rows, args.run_id)
    print(json.dumps({"target_id": target_id, "rows": len(rows), "output": str(args.target_dir / "comparison.json")}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

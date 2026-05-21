#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

from audit_pocs import audit


LOCAL_EDGE_PARAMS = {
    "can_interface",
    "interface",
    "bd_addr",
    "bluetooth_mac",
    "target_mac",
    "frequency",
    "rf_freq",
    "usb_mount_point",
    "firmware_path",
    "target_dir",
}

MANUAL_HINTS = (
    "manual",
    "人工",
    "观察目标",
    "观察车辆",
    "需确认",
    "awaiting manual",
    "requires manual",
    "插入目标车机",
    "u盘",
)


def classify_record(record: dict) -> dict:
    params = set(record.get("meta_required_params") or [])
    hardware_hints = record.get("hardware_hints") or []
    evidence_style = "direct"
    deployment_mode = "cloud_remote"

    if params & LOCAL_EDGE_PARAMS or hardware_hints:
        deployment_mode = "cloud_plus_edge"

    file_path = Path(record["file"])
    text = (Path(__file__).resolve().parent / file_path).read_text(encoding="utf-8", errors="ignore").lower()
    manual_confirmation = any(hint in text for hint in MANUAL_HINTS)
    if manual_confirmation:
        evidence_style = "manual_confirmation"

    if deployment_mode == "cloud_plus_edge" and manual_confirmation:
        readiness = "edge_required_manual_confirmation"
    elif deployment_mode == "cloud_plus_edge":
        readiness = "edge_required"
    elif manual_confirmation:
        readiness = "cloud_reachable_manual_confirmation"
    else:
        readiness = "cloud_ready"

    return {
        "deployment_mode": deployment_mode,
        "manual_confirmation": manual_confirmation,
        "evidence_style": evidence_style,
        "readiness": readiness,
    }


def build_report() -> dict:
    report = audit()
    readiness_counts = {}
    records = []
    for record in report["records"]:
        capability = classify_record(record)
        merged = dict(record)
        merged["capability"] = capability
        records.append(merged)
        key = capability["readiness"]
        readiness_counts[key] = readiness_counts.get(key, 0) + 1

    report["capability_summary"] = readiness_counts
    report["records"] = records
    return report


def render_markdown(report: dict) -> str:
    lines = []
    summary = report["summary"]
    capability_summary = report["capability_summary"]

    lines.append("# PoC Capability Report")
    lines.append("")
    lines.append(f"- Total PoCs: {summary['total']}")
    lines.append(f"- Audit status: green={summary['green']}, yellow={summary['yellow']}, red={summary['red']}")
    lines.append(
        "- Deployment readiness: "
        + ", ".join(f"{key}={value}" for key, value in sorted(capability_summary.items()))
    )
    lines.append("")
    lines.append("| PoC | Category | Audit | Deployment | Manual Confirmation |")
    lines.append("| --- | --- | --- | --- | --- |")

    for record in report["records"]:
        capability = record["capability"]
        lines.append(
            f"| `{record['name']}` | `{record['category']}` | `{record['status']}` | "
            f"`{capability['readiness']}` | `{str(capability['manual_confirmation']).lower()}` |"
        )

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a deployment-facing PoC capability report.")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    parser.add_argument("--output-file", type=Path)
    args = parser.parse_args()

    report = build_report()
    if args.format == "markdown":
        rendered = render_markdown(report)
    else:
        rendered = json.dumps(report, ensure_ascii=False, indent=2)

    print(rendered)
    if args.output_file:
        args.output_file.parent.mkdir(parents=True, exist_ok=True)
        args.output_file.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

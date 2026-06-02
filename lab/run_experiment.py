#!/usr/bin/env python3
import argparse
import ast
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

try:
    import requests
except Exception:
    requests = None


ROOT = Path(__file__).resolve().parents[1]
SERVER_DIR = ROOT / "server"
POCS_DIR = SERVER_DIR / "pocs"
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))


META_KEYS = {
    "meta_display_id",
    "meta_poc_name",
    "meta_cve_id",
    "meta_severity",
    "meta_protocol",
    "meta_target_os",
    "meta_required_params",
    "meta_profiles",
    "meta_destructive_level",
    "is_disruptive",
}

KNOWN_PROFILES = {
    "recon",
    "network",
    "unknown_service",
    "can_gateway",
    "can_extended",
    "bluetooth_recon",
    "bluetooth",
    "wifi",
    "rf",
    "usb_adb",
    "application",
    "advanced_network",
    "local_artifact",
}


def now_id() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _filter_by_ids(items: list[dict], selected_ids: set[str], key: str) -> list[dict]:
    if not selected_ids:
        return items
    return [item for item in items if str(item.get(key) or "") in selected_ids]


def rel_poc(path: Path) -> str:
    return path.relative_to(POCS_DIR).as_posix()


def _has_value(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text) and not text.startswith("REPLACE_")


def _listify(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw = value.replace(";", ",").split(",")
        return [item.strip() for item in raw if item.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()] if str(value).strip() else []


def is_executable_poc(path: Path) -> bool:
    if path.name.startswith("__"):
        return False
    if path.name in {"iv_plugin_base.py", "can_bus_utils.py"}:
        return False
    rel_parts = path.relative_to(POCS_DIR).parts
    if len(rel_parts) > 2:
        return False
    return path.suffix == ".py"


def enrich_poc_meta(meta: dict) -> dict:
    text = " ".join(str(meta.get(k, "")) for k in ("poc_file", "poc_name", "protocol", "required_params")).lower()
    if any(x in text for x in ("can", "uds", "obd")):
        meta["attack_surface"] = "CAN/UDS/OBD"
    elif any(x in text for x in ("bluetooth", "ble", "wifi", "rf", "gps", "tpms", "v2x")):
        meta["attack_surface"] = "无线/外设接口"
    elif any(x in text for x in ("adb", "ssh", "telnet", "mqtt", "rtsp", "http", "someip", "doip", "dlna")):
        meta["attack_surface"] = "网络服务"
    elif any(x in text for x in ("app", "webview", "airplay", "carplay", "mirror")):
        meta["attack_surface"] = "车机APP/应用"
    elif any(x in text for x in ("firmware", "ota", "usb")):
        meta["attack_surface"] = "固件/USB/OTA"
    else:
        meta["attack_surface"] = "其他"
    level = str(meta.get("destructive_level", "Safe")).lower()
    meta["high_risk"] = bool(meta.get("is_disruptive")) or level in {"restart", "dataloss", "brick"}
    meta["profiles"] = infer_poc_profiles(meta)
    return meta


def infer_poc_profiles(meta: dict) -> list[str]:
    explicit = _listify(meta.get("profiles"))
    if explicit:
        return sorted(set(explicit))

    rel = str(meta.get("poc_file") or "")
    category = str(meta.get("category") or "").lower()
    text = " ".join(str(meta.get(k, "")) for k in ("poc_file", "poc_name", "protocol")).lower()
    params = {item.strip() for item in str(meta.get("required_params") or "").split(",") if item.strip()}
    profiles: set[str] = set()

    if rel == "network/15_Dynamic_Unknown_Service_Probe.py":
        profiles.add("unknown_service")
    if category == "reconnaissance":
        if "bd_addr" in params or "bluetooth" in text or "bt_" in text:
            profiles.add("bluetooth_recon")
        elif "target_ip" in params:
            profiles.add("recon")
    elif category == "network":
        if rel == "network/01_USB_ADB_Debug.py" or ("usb" in text and "adb" in text):
            profiles.add("usb_adb")
        elif "target_ip" in params:
            profiles.add("network")
    elif category == "canbus":
        conservative_can = any(token in text for token in ("sniff", "replay", "diag_session", "diagsession"))
        profiles.add("can_gateway" if conservative_can else "can_extended")
    elif category == "wireless":
        if "frequency" in params or "rf" in text or "gps" in text or "tpms" in text or "v2x" in text:
            profiles.add("rf")
        elif "interface" in params or "wifi" in text:
            profiles.add("wifi")
        elif {"bd_addr", "bluetooth_mac", "target_mac"} & params or "bt_" in text or "bluetooth" in text or "blueborne" in text:
            profiles.add("bluetooth")
    elif category == "application":
        if "target_ip" in params:
            profiles.add("application")
        elif not params:
            profiles.add("local_artifact")
    elif category == "advanced":
        if "frequency" in params or "rf" in text or "gps" in text or "tpms" in text or "v2x" in text:
            profiles.add("rf")
        elif "target_ip" in params:
            profiles.add("advanced_network")
        else:
            profiles.add("local_artifact")

    return sorted(profiles)


def parse_poc_meta(path: Path) -> dict:
    meta = {
        "poc_file": rel_poc(path),
        "display_id": "",
        "poc_name": path.stem,
        "category": rel_poc(path).split("/")[0] if "/" in rel_poc(path) else "root",
        "cve_id": "",
        "severity": "",
        "protocol": "",
        "target_os": "",
        "required_params": "",
        "profiles": "",
        "destructive_level": "Safe",
        "is_disruptive": False,
        "parse_error": "",
    }
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except Exception as exc:
        meta["parse_error"] = str(exc)
        return enrich_poc_meta(meta)
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        class_meta = {}
        for item in node.body:
            if not isinstance(item, ast.Assign):
                continue
            try:
                value = ast.literal_eval(item.value)
            except Exception:
                continue
            for target in item.targets:
                if isinstance(target, ast.Name) and target.id in META_KEYS:
                    class_meta[target.id] = value
        if class_meta:
            meta["display_id"] = class_meta.get("meta_display_id") or ""
            meta["poc_name"] = class_meta.get("meta_poc_name") or meta["poc_name"]
            meta["cve_id"] = class_meta.get("meta_cve_id") or ""
            meta["severity"] = class_meta.get("meta_severity") or ""
            meta["protocol"] = class_meta.get("meta_protocol") or ""
            meta["target_os"] = ",".join(class_meta.get("meta_target_os") or [])
            meta["required_params"] = ",".join(class_meta.get("meta_required_params") or [])
            meta["profiles"] = ",".join(class_meta.get("meta_profiles") or [])
            meta["destructive_level"] = class_meta.get("meta_destructive_level") or "Safe"
            meta["is_disruptive"] = bool(class_meta.get("is_disruptive", False))
            break
    return enrich_poc_meta(meta)


def collect_poc_coverage() -> dict:
    pocs = [parse_poc_meta(path) for path in sorted(POCS_DIR.rglob("*.py")) if is_executable_poc(path)]
    by_category = Counter(item["category"] for item in pocs)
    by_surface = Counter(item["attack_surface"] for item in pocs)
    high_risk = [item for item in pocs if item["high_risk"]]
    return {
        "total": len(pocs),
        "by_category": dict(by_category),
        "by_attack_surface": dict(by_surface),
        "high_risk_count": len(high_risk),
        "pocs": pocs,
    }


def _default_params_for_target(target: dict) -> dict:
    params = {}
    if _has_value(target.get("target_ip")):
        params["target_ip"] = target.get("target_ip")
    if _has_value(target.get("can_interface")):
        params["can_interface"] = target.get("can_interface")
    if _has_value(target.get("bluetooth_mac")):
        params["bluetooth_mac"] = target.get("bluetooth_mac")
        params["bd_addr"] = target.get("bluetooth_mac")
        params["target_mac"] = target.get("bluetooth_mac")
    if _has_value(target.get("wifi_interface")):
        params["wifi_interface"] = target.get("wifi_interface")
        params["interface"] = target.get("wifi_interface")
    if _has_value(target.get("rf_frequency")):
        params["rf_frequency"] = target.get("rf_frequency")
        params["frequency"] = target.get("rf_frequency")
    if _has_value(target.get("candidate_ports")):
        params["candidate_ports"] = target.get("candidate_ports")
    if _has_value(target.get("expected_usb_serial")):
        params["expected_usb_serial"] = target.get("expected_usb_serial")
    if _has_value(target.get("usb_device_serial")):
        params["expected_usb_serial"] = target.get("usb_device_serial")
    return params


def _profiles_for_target(target: dict, selector: dict) -> list[str]:
    profiles: list[str] = []
    if _has_value(target.get("target_ip")):
        profiles.extend(["recon", "network"])
        if selector.get("include_unknown_probe", True):
            profiles.append("unknown_service")
    if _has_value(target.get("can_interface")):
        profiles.append("can_gateway")
    if _has_value(target.get("bluetooth_mac")):
        profiles.append("bluetooth_recon")
    if _has_value(target.get("wifi_interface")):
        profiles.append("wifi")
    if _has_value(target.get("rf_frequency")):
        profiles.append("rf")
    if _has_value(target.get("expected_usb_serial")) or _has_value(target.get("usb_device_serial")):
        profiles.append("usb_adb")

    for profile in _listify(selector.get("profiles")):
        if profile not in profiles:
            profiles.append(profile)
    return profiles


def _required_params_satisfied(meta: dict, params: dict) -> bool:
    required = _listify(meta.get("required_params"))
    for name in required:
        if not _has_value(params.get(name)):
            return False
    return True


def _build_auto_poc_entries(target: dict, coverage: dict) -> list[dict]:
    selector = target.get("selector", {}) if isinstance(target.get("selector"), dict) else {}
    selected_profiles = _profiles_for_target(target, selector)
    allow_disruptive = bool(selector.get("allow_disruptive", False))
    exclude_pocs = set(_listify(selector.get("exclude_pocs")))
    include_pocs = _listify(selector.get("include_pocs"))
    param_overrides = target.get("param_overrides", {}) if isinstance(target.get("param_overrides"), dict) else {}
    default_params = _default_params_for_target(target)

    entries: list[dict] = []
    seen = set()
    meta_by_file = {item["poc_file"]: item for item in coverage.get("pocs", [])}

    candidates = []
    for meta in coverage.get("pocs", []):
        poc_file = meta.get("poc_file")
        if not poc_file or poc_file in exclude_pocs:
            continue
        meta_profiles = set(_listify(meta.get("profiles")))
        matching_profiles = [profile for profile in selected_profiles if profile in meta_profiles]
        if matching_profiles:
            candidates.append((meta, matching_profiles[0]))

    for poc_file in include_pocs:
        meta = meta_by_file.get(poc_file)
        if meta and not any(item[0].get("poc_file") == poc_file for item in candidates):
            candidates.append((meta, "explicit"))

    for meta, profile in candidates:
        poc_file = meta["poc_file"]
        if poc_file in seen:
            continue
        if meta.get("high_risk") and not allow_disruptive:
            continue
        params = dict(default_params)
        if isinstance(param_overrides.get(poc_file), dict):
            params.update(param_overrides[poc_file])
        if not _required_params_satisfied(meta, params):
            continue
        entries.append({
            "filename": poc_file,
            "params": params,
            "expected": "evidence_or_no_confirmed_risk",
            "auto_profile": profile,
            "target_profiles": selected_profiles,
        })
        seen.add(poc_file)

    return entries


def resolve_scan_targets(config: dict, coverage: dict, output_dir: Path) -> list[dict]:
    resolved = []
    for target in config.get("scan_targets", []):
        target_copy = dict(target)
        existing_pocs = target_copy.get("pocs")
        auto_select = bool(target_copy.get("auto_select"))
        if auto_select or not existing_pocs:
            target_copy["pocs"] = _build_auto_poc_entries(target_copy, coverage)
            target_copy["resolved_mode"] = "auto"
        else:
            target_copy["resolved_mode"] = "manual"
        resolved.append(target_copy)
    write_json(output_dir / "resolved_scan_targets.json", resolved)
    return resolved


def should_block(meta_map: dict, filename: str, params: dict) -> tuple[bool, str, dict]:
    key = filename.replace("\\", "/")
    base = key.rsplit("/", 1)[-1]
    meta = meta_map.get(key) or meta_map.get(base) or {}
    level = str(meta.get("destructive_level") or "").lower()
    high_risk = bool(meta.get("is_disruptive")) or level in {"restart", "dataloss", "brick"}
    if high_risk and params.get("allow_disruptive") not in {True, "true", "True", "1", 1}:
        return True, "high-risk PoC requires explicit allow_disruptive=true", meta
    return False, "", meta


def run_poc_api(api_base: str, filename: str, params: dict, session_id: str) -> dict:
    if requests is None:
        return {"success": False, "error": "requests is not installed"}
    started = time.time()
    try:
        resp = requests.post(
            f"{api_base.rstrip('/')}/api/run_poc",
            json={"filename": filename, "params": params, "session_id": session_id},
            timeout=120,
        )
        elapsed = round(time.time() - started, 3)
        if resp.headers.get("content-type", "").startswith("application/json"):
            payload = resp.json()
        else:
            payload = {"raw": resp.text}
        payload["http_status"] = resp.status_code
        payload["elapsed_seconds"] = elapsed
        if not resp.ok and not payload.get("error"):
            payload["success"] = False
            payload["error"] = (
                payload.get("message")
                or payload.get("raw")
                or f"HTTP {resp.status_code}"
            )
        return payload
    except Exception as exc:
        return {"success": False, "error": str(exc), "elapsed_seconds": round(time.time() - started, 3)}


def collect_edge_capability(config: dict, output_dir: Path) -> list[dict]:
    rows = []
    for item in config.get("edge_capability_targets", []):
        row = dict(item)
        row["host_tools_checked"] = True
        for tool in ("adb", "bluetoothctl", "hciconfig", "ip", "iw", "lsusb", "candump", "cansend", "hackrf_info"):
            row[f"tool_{tool}"] = bool(shutil_which(tool))
        rows.append(row)
    write_json(output_dir / "edge_capabilities.json", rows)
    return rows


def shutil_which(cmd: str) -> str:
    from shutil import which
    return which(cmd) or ""


def run_scan_targets(config: dict, coverage: dict, output_dir: Path) -> list[dict]:
    meta_map = {}
    for meta in coverage["pocs"]:
        meta_map[meta["poc_file"]] = meta
        meta_map[meta["poc_file"].rsplit("/", 1)[-1]] = meta

    scan_targets = resolve_scan_targets(config, coverage, output_dir)
    rows = []
    for target in scan_targets:
        for poc in target.get("pocs", []):
            filename = poc["filename"]
            params = dict(poc.get("params", {}))
            params.setdefault("target_ip", target.get("target_ip"))
            blocked, reason, meta = should_block(meta_map, filename, params)
            session_id = f"{target.get('target_id')}_{filename.rsplit('/', 1)[-1]}_{now_id()}"
            evidence_file = output_dir / "poc_runs" / f"{session_id}.json"
            started = time.time()
            if blocked:
                result = {
                    "success": False,
                    "blocked": True,
                    "requires_approval": True,
                    "error": reason,
                    "vulnerable": False,
                    "evidence": "",
                    "logs": [],
                    "elapsed_seconds": 0,
                }
            else:
                result = run_poc_api(config.get("api_base", "http://127.0.0.1:5002"), filename, params, session_id)
            elapsed = result.get("elapsed_seconds", round(time.time() - started, 3))
            write_json(evidence_file, result)
            rows.append({
                "target_id": target.get("target_id"),
                "target_name": target.get("target_name"),
                "target_ip": target.get("target_ip"),
                "poc_file": filename,
                "poc_display_id": meta.get("display_id", ""),
                "poc_name": meta.get("poc_name", filename),
                "category": meta.get("category", ""),
                "attack_surface": meta.get("attack_surface", ""),
                "auto_profile": poc.get("auto_profile", ""),
                "target_profiles": poc.get("target_profiles", []),
                "destructive_level": meta.get("destructive_level", ""),
                "is_high_risk": meta.get("high_risk", False),
                "blocked": bool(result.get("blocked") or result.get("requires_approval")),
                "requires_approval": bool(result.get("requires_approval")),
                "status": (
                    "blocked"
                    if result.get("blocked") or result.get("requires_approval")
                    else (
                        "error"
                        if result.get("error") or int(result.get("http_status") or 200) >= 400 or result.get("success") is False
                        else "completed"
                    )
                ),
                "elapsed_seconds": elapsed,
                "vulnerable": bool(result.get("vulnerable")),
                "evidence": result.get("evidence") or result.get("output") or result.get("error") or "",
                "evidence_file": str(evidence_file),
                "expected": poc.get("expected", ""),
            })
    write_json(output_dir / "scan_results.json", rows)
    return rows


def run_agent_tasks(config: dict, output_dir: Path) -> list[dict]:
    rows = []
    try:
        from agent_orchestrator import AgentOrchestrator
    except Exception as exc:
        write_json(output_dir / "agent_error.json", {"error": str(exc)})
        return rows

    for task in config.get("agent_tasks", []):
        started = time.time()
        report_file = output_dir / "agent_runs" / f"{task.get('task_id')}_{now_id()}.json"
        try:
            orch = AgentOrchestrator(
                target_ip=task["target_ip"],
                target_name=task.get("target_name", task["task_id"]),
                llm_config=config.get("ai_config", {}),
                can_interface=task.get("can_interface", ""),
                bluetooth_mac=task.get("bluetooth_mac", ""),
                wifi_interface=task.get("wifi_interface", ""),
                expected_usb_serial=task.get("expected_usb_serial") or task.get("usb_device_serial") or "",
            )
            report = orch.run_full_assessment()
        except Exception as exc:
            report = {"error": str(exc), "structured": {}, "findings": [], "phase_records": []}
        elapsed = round(time.time() - started, 3)
        write_json(report_file, report)
        structured = report.get("structured", {}) or {}
        attack_plan = structured.get("attack_plan", {}).get("items", []) or []
        execution = structured.get("execution", {}).get("items", []) or []
        reflector = structured.get("reflector", {}) or {}
        rows.append({
            "task_id": task.get("task_id"),
            "target_ip": task.get("target_ip"),
            "method": task.get("method", "ours_full"),
            "planned_poc_count": len(attack_plan),
            "executed_poc_count": len(execution),
            "reflection_reentry_count": int(report.get("reflector_reentry_count", 0) or 0),
            "reflection_next_action": reflector.get("next_action", ""),
            "reflection_issue_count": len(reflector.get("issues", []) or []),
            "retry_or_error_count": sum(1 for item in execution if item.get("error")),
            "finding_count": len(report.get("findings", []) or []),
            "elapsed_seconds": elapsed,
            "report_file": str(report_file),
        })
    write_json(output_dir / "agent_orchestration.json", rows)
    return rows


def collect_manual_comparison(config: dict, scan_rows: list[dict], output_dir: Path) -> list[dict]:
    platform_time = {}
    platform_count = Counter()
    for row in scan_rows:
        platform_time[row["target_id"]] = platform_time.get(row["target_id"], 0) + float(row.get("elapsed_seconds") or 0)
        platform_count[row["target_id"]] += 1
    rows = []
    for item in config.get("manual_comparison", []):
        row = dict(item)
        if row.get("platform_elapsed_seconds") in {"", None}:
            row["platform_elapsed_seconds"] = round(platform_time.get(row.get("target_id"), 0), 3)
        if row.get("platform_poc_count") in {"", None}:
            row["platform_poc_count"] = platform_count.get(row.get("target_id"), 0)
        rows.append(row)
    write_json(output_dir / "comparison.json", rows)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect advisor-required experiment data.")
    parser.add_argument("--config", type=Path, default=Path("lab/experiment_config.json"))
    parser.add_argument("--output-dir", type=Path, default=Path("lab/evidence"))
    parser.add_argument("--skip-agent", action="store_true")
    parser.add_argument("--target-id", action="append", default=[], help="Only run the specified scan target_id. Repeatable.")
    parser.add_argument("--agent-task-id", action="append", default=[], help="Only run the specified agent task_id. Repeatable.")
    args = parser.parse_args()
    config = read_json(args.config)
    selected_target_ids = {item.strip() for item in args.target_id if str(item).strip()}
    selected_agent_task_ids = {item.strip() for item in args.agent_task_id if str(item).strip()}
    if selected_target_ids:
        config["scan_targets"] = _filter_by_ids(config.get("scan_targets", []), selected_target_ids, "target_id")
        config["manual_comparison"] = _filter_by_ids(config.get("manual_comparison", []), selected_target_ids, "target_id")
        config["typical_cases"] = _filter_by_ids(config.get("typical_cases", []), selected_target_ids, "target_id")
    if selected_agent_task_ids:
        config["agent_tasks"] = _filter_by_ids(config.get("agent_tasks", []), selected_agent_task_ids, "task_id")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    coverage = collect_poc_coverage()
    write_json(args.output_dir / "poc_coverage.json", coverage)
    scan_rows = run_scan_targets(config, coverage, args.output_dir)
    edge_rows = collect_edge_capability(config, args.output_dir)
    agent_rows = [] if args.skip_agent else run_agent_tasks(config, args.output_dir)
    comparison_rows = collect_manual_comparison(config, scan_rows, args.output_dir)
    write_json(args.output_dir / "typical_cases.json", config.get("typical_cases", []))

    summary = {
        "poc_total": coverage["total"],
        "scan_execution_count": len(scan_rows),
        "agent_task_count": len(agent_rows),
        "edge_target_count": len(edge_rows),
        "comparison_count": len(comparison_rows),
        "output_dir": str(args.output_dir),
    }
    write_json(args.output_dir / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

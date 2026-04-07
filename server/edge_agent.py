#!/usr/bin/env python3
import argparse
import json
import socket
import time
from pathlib import Path

import requests

from config import get_config
from edge_capability_probe import probe as probe_capabilities
from poc_worker import SERVER_DIR, get_poc_worker


CONFIG = get_config()
STATE_FILE = SERVER_DIR / ".edge-agent-state.json"


def _load_state(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_state(path: Path, state: dict) -> None:
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _headers(state: dict) -> dict:
    return {
        "X-Edge-Agent-Id": state["agent_id"],
        "X-Edge-Token": state["edge_token"],
    }


def register(edge_api: str, enrollment_token: str, state_path: Path, *, display_name: str | None = None, site_name: str | None = None) -> dict:
    state = _load_state(state_path)
    resolved_display_name = display_name or socket.gethostname()
    resolved_site_name = site_name or state.get("site_name") or socket.gethostname()
    payload = {
        "agent_id": state.get("agent_id"),
        "display_name": resolved_display_name,
        "hostname": socket.gethostname(),
        "site_name": resolved_site_name,
        "capabilities": probe_capabilities(),
        "metadata": {
            "platform": "edge-agent",
        },
    }
    response = requests.post(
        f"{edge_api}/api/edge/register",
        headers={"X-Edge-Enrollment-Token": enrollment_token},
        json=payload,
        timeout=20,
    )
    response.raise_for_status()
    body = response.json()
    state.update(
        {
            "agent_id": body["agent_id"],
            "edge_token": body["edge_token"],
            "site_name": body.get("agent", {}).get("site_name") or payload["site_name"],
        }
    )
    _save_state(state_path, state)
    return state


def heartbeat(edge_api: str, state: dict) -> dict:
    payload = {
        "status": "online",
        "capabilities": probe_capabilities(),
        "metadata": {
            "hostname": socket.gethostname(),
        },
    }
    response = requests.post(
        f"{edge_api}/api/edge/heartbeat",
        headers=_headers(state),
        json=payload,
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def fetch_next_task(edge_api: str, state: dict) -> dict | None:
    response = requests.get(
        f"{edge_api}/api/edge/tasks/next",
        headers=_headers(state),
        timeout=30,
    )
    response.raise_for_status()
    body = response.json()
    return body.get("task")


def execute_task(task: dict) -> dict:
    worker = get_poc_worker("local_sandbox")
    poc_path = str((SERVER_DIR / "pocs" / task["poc_filename"]).resolve())
    if not Path(poc_path).exists():
        basename = Path(task["poc_filename"]).name
        matches = list((SERVER_DIR / "pocs").rglob(basename))
        if not matches:
            raise FileNotFoundError(f"PoC file not found on edge agent: {task['poc_filename']}")
        poc_path = str(matches[0].resolve())

    plan = worker.prepare(
        poc_path,
        dict(task.get("params") or {}),
        trace_id=task.get("trace_id") or task["task_id"],
        session_id=task.get("session_id") or "edge",
        timeout_seconds=int((task.get("params") or {}).get("sandbox_timeout_seconds", 60)),
    )
    result = worker.run_once(plan)
    plugin_results = result.get("plugin_results", {})
    return {
        "success": bool(result.get("success")),
        "logs": result.get("logs", []),
        "errors": [plugin_results.get("error")] if "error" in plugin_results else [],
        "vulnerable": plugin_results.get("vulnerable", False),
        "evidence": plugin_results.get("evidence", ""),
        "cve_id": plugin_results.get("cve_id", ""),
        "elapsed_seconds": result.get("elapsed_seconds", 0),
        "plugin_results": plugin_results,
        "sandbox_profile": result.get("sandbox_profile", {}),
        "security_profile": result.get("security_profile", {}),
        "worker_mode": result.get("worker_mode", "local_sandbox"),
    }


def submit_result(edge_api: str, state: dict, task_id: str, result: dict) -> dict:
    response = requests.post(
        f"{edge_api}/api/edge/tasks/{task_id}/result",
        headers=_headers(state),
        json=result,
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def run_loop(edge_api: str, state: dict, poll_seconds: int) -> None:
    while True:
        try:
            heartbeat(edge_api, state)
            task = fetch_next_task(edge_api, state)
            if task:
                try:
                    result = execute_task(task)
                except Exception as exc:
                    result = {
                        "success": False,
                        "logs": [],
                        "errors": [str(exc)],
                        "vulnerable": False,
                        "evidence": "",
                        "cve_id": "",
                        "elapsed_seconds": 0,
                        "plugin_results": {"error": str(exc)},
                        "sandbox_profile": {},
                        "security_profile": {},
                        "worker_mode": "local_sandbox",
                    }
                submit_result(edge_api, state, task["task_id"], result)
        except Exception as exc:
            print(json.dumps({"edge_agent_error": str(exc)}, ensure_ascii=False))
        time.sleep(poll_seconds)


def main() -> int:
    parser = argparse.ArgumentParser(description="AutoSec edge agent")
    parser.add_argument("--register", action="store_true", help="Register this edge agent using AUTOSEC_EDGE_ENROLLMENT_TOKEN")
    parser.add_argument("--daemon", action="store_true", help="Run in daemon mode: continuously poll for tasks (default is single-run)")
    parser.add_argument("--once", action="store_true", help="(Deprecated, now default) Heartbeat once and execute at most one task")
    parser.add_argument("--state-file", type=Path, default=STATE_FILE)
    parser.add_argument("--poll-seconds", type=int, default=30)
    parser.add_argument("--edge-api", default=CONFIG.autosec_api)
    parser.add_argument("--display-name", default=socket.gethostname())
    parser.add_argument("--site-name", default=None)
    args = parser.parse_args()

    state = _load_state(args.state_file)
    enrollment_token = CONFIG.edge_enrollment_token

    if args.register or not state.get("edge_token"):
        if not enrollment_token:
            raise SystemExit("AUTOSEC_EDGE_ENROLLMENT_TOKEN is required for registration.")
        state = register(
            args.edge_api,
            enrollment_token,
            args.state_file,
            display_name=args.display_name,
            site_name=args.site_name,
        )

    # Default: single execution (heartbeat + at most one task)
    if not args.daemon:
        heartbeat(args.edge_api, state)
        task = fetch_next_task(args.edge_api, state)
        if task:
            try:
                result = execute_task(task)
            except Exception as exc:
                result = {
                    "success": False,
                    "logs": [],
                    "errors": [str(exc)],
                    "vulnerable": False,
                    "evidence": "",
                    "cve_id": "",
                    "elapsed_seconds": 0,
                    "plugin_results": {"error": str(exc)},
                    "sandbox_profile": {},
                    "security_profile": {},
                    "worker_mode": "local_sandbox",
                }
            submit_result(args.edge_api, state, task["task_id"], result)
        print(json.dumps({"ok": True, "agent_id": state["agent_id"]}, ensure_ascii=False, indent=2))
        return 0

    # Daemon mode: continuous polling loop
    run_loop(args.edge_api, state, args.poll_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


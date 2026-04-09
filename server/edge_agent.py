#!/usr/bin/env python3
import argparse
import json
import os
import socket
import sys
import time
from pathlib import Path

import requests

from edge_capability_probe import probe as probe_capabilities
from poc_worker import POCS_DIR, get_poc_worker
from poc_registry import get_poc_code, has_builtin_poc


def _is_packaged_runtime() -> bool:
    return bool(
        getattr(sys, "frozen", False)
        or hasattr(sys, "__compiled__")
        or os.environ.get("NUITKA_ONEFILE_PARENT")
    )



def _default_state_path() -> Path:
    override = (os.environ.get("AUTOSEC_EDGE_STATE_FILE") or "").strip()
    if override:
        return Path(override).expanduser()
    # For commercial deployment, always persist state in a known home directory location
    # to avoid data loss in ephemeral onefile/container environments.
    return Path.home() / ".autosec-edge" / "edge-state.json"


STATE_FILE = _default_state_path()


def _load_state(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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
            "edge_api": edge_api,
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
    task = body.get("task")
    if task:
        task = _hydrate_task_if_needed(edge_api, state, task)
    return task


def _local_poc_exists(task: dict) -> bool:
    return _resolve_local_poc_path(task["poc_filename"]) is not None or has_builtin_poc(task["poc_filename"])


def _resolve_local_poc_path(poc_filename: str) -> str | None:
    poc_path = (POCS_DIR / poc_filename).resolve()
    if poc_path.exists():
        return str(poc_path)

    basename = Path(poc_filename).name
    for candidate in POCS_DIR.rglob(basename):
        if candidate.exists():
            return str(candidate.resolve())
    return None


def _hydrate_task_if_needed(edge_api: str, state: dict, task: dict) -> dict:
    if task.get("poc_code") or _local_poc_exists(task):
        return task

    response = requests.get(
        f"{edge_api}/api/edge/tasks/{task['task_id']}/payload",
        headers=_headers(state),
        timeout=30,
    )
    response.raise_for_status()
    body = response.json()
    return body.get("task") or task


def execute_task(task: dict) -> dict:
    worker = get_poc_worker("local_sandbox")
    poc_code = task.get("poc_code")
    normalized_builtin = None
    poc_path = _resolve_local_poc_path(task["poc_filename"])
    if poc_path is None:
        builtin_code, normalized_builtin = get_poc_code(task["poc_filename"])
        if builtin_code:
            poc_code = poc_code or builtin_code
            poc_path = str((POCS_DIR / (normalized_builtin or task["poc_filename"])).resolve())
    if poc_path is None:
        poc_path = str((POCS_DIR / task["poc_filename"]).resolve())
    
    # If we have streamed code, we don't strictly require the file to exist on disk yet
    # as the worker will handle ephemeral creation.
    if not poc_code and not Path(poc_path).exists():
        raise FileNotFoundError(
            f"PoC file not found on edge agent and no embedded/dynamic code provided: {task['poc_filename']} "
            f"(searched under {POCS_DIR})"
        )

    plan = worker.prepare(
        poc_path,
        dict(task.get("params") or {}),
        trace_id=task.get("trace_id") or task["task_id"],
        session_id=task.get("session_id") or "edge",
        timeout_seconds=int((task.get("params") or {}).get("sandbox_timeout_seconds", 60)),
        poc_code=poc_code,
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


def _resolve_edge_api(cli_value: str | None, state: dict) -> str:
    return (
        (cli_value or "").strip()
        or (os.environ.get("AUTOSEC_API") or "").strip()
        or str(state.get("edge_api") or "").strip()
    )


def main() -> int:
    if _is_packaged_runtime():
        try:
            os.environ.setdefault("AUTOSEC_EDGE_EXECUTABLE", str(Path(sys.argv[0]).resolve()))
        except Exception:
            if sys.argv and sys.argv[0]:
                os.environ.setdefault("AUTOSEC_EDGE_EXECUTABLE", sys.argv[0])

    parser = argparse.ArgumentParser(description="AutoSec edge agent")
    parser.add_argument("--register", action="store_true", help="Register this edge agent using enrollment token")
    parser.add_argument("--daemon", action="store_true", help="Run in daemon mode: continuously poll for tasks (default is single-run)")
    parser.add_argument("--once", action="store_true", help="(Deprecated, now default) Heartbeat once and execute at most one task")
    parser.add_argument("--state-file", type=Path, default=STATE_FILE)
    parser.add_argument("--poll-seconds", type=int, default=5)
    parser.add_argument("--edge-api", default=None, help="URL of the AutoSec cloud server (e.g. https://your-server.com)")
    parser.add_argument("--enrollment-token", default=os.environ.get("AUTOSEC_EDGE_ENROLLMENT_TOKEN") or None, help="One-time enrollment token (from Web UI)")
    parser.add_argument("--display-name", default=socket.gethostname())
    parser.add_argument("--site-name", default=None)
    parser.add_argument("--run-sandbox", nargs=2, metavar=("POC_PATH", "PARAMS_JSON"), help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.run_sandbox:
        from sandbox_runner import main as sandbox_main

        sys.argv = [sys.argv[0], *args.run_sandbox]
        return sandbox_main()

    state = _load_state(args.state_file)
    edge_api = _resolve_edge_api(args.edge_api, state)
    enrollment_token = args.enrollment_token

    if not edge_api:
        raise SystemExit(
            "Edge API base URL is required.\n"
            "Pass --edge-api <SERVER_URL>, set AUTOSEC_API, or register once so it is persisted in the edge state file."
        )

    if args.register or not state.get("edge_token"):
        if not enrollment_token:
            raise SystemExit(
                "Enrollment token is required for registration.\n"
                "Get one from the Web UI (Edge Control Plane → 申请部署令牌),\n"
                "then run:  python edge_agent.py --register --edge-api <SERVER_URL> --enrollment-token <TOKEN>"
            )
        state = register(
            edge_api,
            enrollment_token,
            args.state_file,
            display_name=args.display_name,
            site_name=args.site_name,
        )

    # Default: single execution (heartbeat + at most one task)
    if not args.daemon:
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
        print(json.dumps({"ok": True, "agent_id": state["agent_id"]}, ensure_ascii=False, indent=2))
        return 0

    # Daemon mode: continuous polling loop
    run_loop(edge_api, state, args.poll_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

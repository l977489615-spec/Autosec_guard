import ast
import errno
import ipaddress
import json
import os
import resource
import socket
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


SERVER_DIR = Path(__file__).resolve().parent
POCS_DIR = SERVER_DIR / "pocs"
SANDBOX_RUNNER = SERVER_DIR / "sandbox_runner.py"


def _parse_int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except Exception:
        return int(default)


def _allowed_hosts_from_env() -> set[str]:
    hosts = set()
    raw_hosts = os.environ.get("SANDBOX_ALLOWED_HOSTS", "")
    for item in raw_hosts.split(","):
        item = item.strip()
        if item:
            hosts.add(item)
    return hosts


def _is_allowed_destination(host: Any, allowed_hosts: set[str]) -> bool:
    if not allowed_hosts:
        return True

    host = str(host).strip()
    if not host:
        return False
    if host in allowed_hosts:
        return True

    try:
        parsed = ipaddress.ip_address(host)
        return str(parsed) in allowed_hosts
    except Exception:
        return False


def _extract_security_profile(poc_path: str) -> dict:
    profile = {
        "poc_name": os.path.basename(poc_path),
        "cve_id": "",
        "severity": "",
        "protocol": "",
        "target_os": [],
        "required_params": [],
        "destructive_level": "Safe",
        "is_disruptive": False,
    }

    try:
        with open(poc_path, "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=poc_path)
        metadata_keys = {
            "meta_poc_name",
            "meta_cve_id",
            "meta_severity",
            "meta_protocol",
            "meta_target_os",
            "meta_required_params",
            "meta_destructive_level",
            "is_disruptive",
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            class_meta = {}
            for body_item in node.body:
                if not isinstance(body_item, ast.Assign):
                    continue
                try:
                    value = ast.literal_eval(body_item.value)
                except Exception:
                    continue
                for target_node in body_item.targets:
                    if isinstance(target_node, ast.Name) and target_node.id in metadata_keys:
                        class_meta[target_node.id] = value
            if class_meta:
                profile["poc_name"] = class_meta.get("meta_poc_name") or profile["poc_name"]
                profile["cve_id"] = class_meta.get("meta_cve_id") or profile["cve_id"]
                profile["severity"] = class_meta.get("meta_severity") or profile["severity"]
                profile["protocol"] = class_meta.get("meta_protocol") or profile["protocol"]
                profile["target_os"] = class_meta.get("meta_target_os") or profile["target_os"]
                profile["required_params"] = class_meta.get("meta_required_params") or profile["required_params"]
                profile["destructive_level"] = class_meta.get("meta_destructive_level") or profile["destructive_level"]
                profile["is_disruptive"] = bool(class_meta.get("is_disruptive", profile["is_disruptive"]))
                break
    except Exception as exc:
        profile["parse_error"] = str(exc)
    return profile


def _requires_disruptive_approval(profile: dict, params: dict) -> bool:
    if params.get("allow_disruptive") in (True, "true", "True", "1", 1):
        return False
    if profile.get("is_disruptive"):
        return True
    destructive_level = str(profile.get("destructive_level") or "").lower()
    return destructive_level in {"restart", "dataloss", "brick"}


def _build_sandbox_env(params: dict, allowed_hosts: Optional[List[str]] = None) -> dict:
    env = os.environ.copy()
    env["SANDBOX_CPU_SECONDS"] = str(params.get("sandbox_cpu_seconds", _parse_int_env("SANDBOX_CPU_SECONDS", 60)))
    env["SANDBOX_MEMORY_MB"] = str(params.get("sandbox_memory_mb", _parse_int_env("SANDBOX_MEMORY_MB", 256)))
    env["SANDBOX_OUTPUT_MB"] = str(params.get("sandbox_output_mb", _parse_int_env("SANDBOX_OUTPUT_MB", 8)))
    env["SANDBOX_NOFILE"] = str(params.get("sandbox_nofile", _parse_int_env("SANDBOX_NOFILE", 256)))
    env["SANDBOX_ALLOWED_HOSTS"] = ",".join(allowed_hosts or [])
    return env


def _parse_plugin_result(stdout_text: str) -> tuple[list[str], dict]:
    parts = stdout_text.split("===RESULT_TOKEN===")
    logs_text = parts[0]
    result_json = parts[1].strip() if len(parts) > 1 else "{}"
    try:
        plugin_results = json.loads(result_json)
    except Exception:
        plugin_results = {"vulnerable": False, "error": "Failed to parse result", "raw": result_json}
    return logs_text.splitlines(), plugin_results


def _build_command(poc_path: str, params: dict, use_unbuffered: bool = False) -> list[str]:
    runner_args = [str(SANDBOX_RUNNER), poc_path, json.dumps(params)]
    if use_unbuffered:
        return [sys.executable, "-u", *runner_args]
    return [sys.executable, *runner_args]


@dataclass
class PocWorkerPlan:
    worker_mode: str
    poc_path: str
    poc_filename: str
    trace_id: str
    session_id: str
    params: dict
    security_profile: dict
    sandbox_profile: dict
    allowed_hosts: List[str]
    command: list[str]
    env: dict
    timeout_seconds: int = 60


class LocalSandboxPocWorker:
    worker_mode = "local_sandbox"

    def __init__(self, worker_mode: Optional[str] = None):
        if worker_mode:
            self.worker_mode = worker_mode

    def prepare(
        self,
        poc_path: str,
        params: dict,
        *,
        trace_id: str,
        session_id: str,
        timeout_seconds: int = 60,
    ) -> PocWorkerPlan:
        poc_filename = os.path.basename(poc_path)
        security_profile = _extract_security_profile(poc_path)
        allowed_hosts = []
        if params.get("target_ip"):
            allowed_hosts.append(str(params["target_ip"]))

        sandbox_profile = {
            "cpu_seconds": int(params.get("sandbox_cpu_seconds", _parse_int_env("SANDBOX_CPU_SECONDS", 60))),
            "memory_mb": int(params.get("sandbox_memory_mb", _parse_int_env("SANDBOX_MEMORY_MB", 256))),
            "output_mb": int(params.get("sandbox_output_mb", _parse_int_env("SANDBOX_OUTPUT_MB", 8))),
            "nofile": int(params.get("sandbox_nofile", _parse_int_env("SANDBOX_NOFILE", 256))),
            "allowed_hosts": allowed_hosts,
        }

        return PocWorkerPlan(
            worker_mode=self.worker_mode,
            poc_path=poc_path,
            poc_filename=poc_filename,
            trace_id=trace_id,
            session_id=session_id,
            params=params,
            security_profile=security_profile,
            sandbox_profile=sandbox_profile,
            allowed_hosts=allowed_hosts,
            command=_build_command(poc_path, params, use_unbuffered=False),
            env=_build_sandbox_env(params, allowed_hosts),
            timeout_seconds=timeout_seconds,
        )

    def run_once(self, plan: PocWorkerPlan) -> dict:
        start_time = time.time()
        proc = subprocess.Popen(
            plan.command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=plan.env,
            start_new_session=True,
        )
        try:
            stdout_text, _ = proc.communicate(timeout=plan.timeout_seconds)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_text, _ = proc.communicate()
            elapsed = round(time.time() - start_time, 2)
            logs, plugin_results = _parse_plugin_result(stdout_text or "")
            return {
                "success": False,
                "returncode": proc.returncode,
                "logs": logs,
                "plugin_results": plugin_results,
                "elapsed_seconds": elapsed,
                "security_profile": plan.security_profile,
                "sandbox_profile": plan.sandbox_profile,
                "trace_id": plan.trace_id,
                "worker_mode": plan.worker_mode,
                "timeout": True,
            }

        elapsed = round(time.time() - start_time, 2)
        logs, plugin_results = _parse_plugin_result(stdout_text or "")
        return {
            "success": proc.returncode == 0 and "error" not in plugin_results,
            "returncode": proc.returncode,
            "logs": logs,
            "plugin_results": plugin_results,
            "elapsed_seconds": elapsed,
            "security_profile": plan.security_profile,
            "sandbox_profile": plan.sandbox_profile,
            "trace_id": plan.trace_id,
            "worker_mode": plan.worker_mode,
        }

    def iter_stream(self, plan: PocWorkerPlan) -> Iterator[dict]:
        proc = subprocess.Popen(
            _build_command(plan.poc_path, plan.params, use_unbuffered=True),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=plan.env,
            start_new_session=True,
        )

        result_json = "{}"
        collecting_result = False
        start_time = time.time()

        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if "===RESULT_TOKEN===" in line:
                    collecting_result = True
                    continue

                if collecting_result:
                    result_json += line
                else:
                    yield {"type": "log", "message": line.strip()}

            proc.wait(timeout=plan.timeout_seconds)
            try:
                plugin_results = json.loads(result_json) if result_json.strip() != "{}" else {}
            except Exception as exc:
                plugin_results = {"error": f"Failed to parse result: {exc}", "raw": result_json}

            elapsed = round(time.time() - start_time, 2)
            success = proc.returncode == 0 and "error" not in plugin_results
            yield {
                "type": "result",
                "success": success,
                "vulnerable": plugin_results.get("vulnerable", False),
                "evidence": plugin_results.get("evidence", ""),
                "cve_id": plugin_results.get("cve_id", ""),
                "elapsed_seconds": elapsed,
                "errors": [plugin_results.get("error")] if "error" in plugin_results else [],
                "trace_id": plan.trace_id,
                "security_profile": plan.security_profile,
                "sandbox_profile": plan.sandbox_profile,
                "plugin_results": plugin_results,
                "worker_mode": plan.worker_mode,
            }
        except Exception as exc:
            yield {
                "type": "result",
                "success": False,
                "errors": [str(exc), traceback.format_exc()],
                "trace_id": plan.trace_id,
                "security_profile": plan.security_profile,
                "sandbox_profile": plan.sandbox_profile,
                "worker_mode": plan.worker_mode,
            }


def get_poc_worker(mode: Optional[str] = None):
    worker_mode = (mode or os.environ.get("AUTOSEC_POC_WORKER_MODE", "local_sandbox")).strip().lower()
    # Future extension point: docker, k8s, remote queue workers.
    return LocalSandboxPocWorker(worker_mode=worker_mode)
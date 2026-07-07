"""Runtime helpers for PoCs migrated into the IVIVulnerabilityPlugin contract."""
from __future__ import annotations

import contextlib
import io
import logging
import os
import sys
from typing import Any, Callable


def inject_runtime_env(params: dict[str, Any]) -> None:
    target_ip = params.get("target_ip")
    if target_ip not in (None, ""):
        os.environ["AUTOSEC_TARGET_IP"] = str(target_ip)

    env_param_map = {
        "android_source_text": "AUTOSEC_ANDROID_SOURCE_TEXT",
        "android_source_fixture": "AUTOSEC_ANDROID_SOURCE_FIXTURE",
        "android_manifest_text": "AUTOSEC_ANDROID_MANIFEST_TEXT",
        "android_manifest": "AUTOSEC_ANDROID_MANIFEST",
        "sqlite_fixture_dir": "AUTOSEC_SQLITE_FIXTURE_DIR",
        "app_data_fixture_dir": "AUTOSEC_APP_DATA_FIXTURE_DIR",
        "log_text": "AUTOSEC_LOG_TEXT",
        "log_fixture": "AUTOSEC_LOG_FIXTURE",
        "can_log_fixture": "AUTOSEC_CAN_LOG_FIXTURE",
        "uds_log_text": "AUTOSEC_UDS_LOG_TEXT",
        "uds_log_fixture": "AUTOSEC_UDS_LOG_FIXTURE",
        "doip_port": "AUTOSEC_DOIP_PORT",
    }
    for key, env_name in env_param_map.items():
        value = params.get(key)
        if value not in (None, ""):
            os.environ[env_name] = str(value)

    for key, value in params.items():
        if str(key).startswith("AUTOSEC_") and value not in (None, ""):
            os.environ[str(key)] = str(value)

    for key in ("expected_usb_serial", "serial", "can_interface", "bluetooth_mac"):
        value = params.get(key)
        if value not in (None, ""):
            os.environ[f"AUTOSEC_{key.upper()}"] = str(value)


def execute_check_callable(check_callable: Callable[[], Any], plugin: Any) -> dict[str, Any]:
    inject_runtime_env(plugin.params or {})
    stdout_buffer = io.StringIO()
    log_buffer = io.StringIO()
    handler = logging.StreamHandler(log_buffer)
    handler.setLevel(logging.INFO)
    root = logging.getLogger()
    previous_level = root.level
    root.addHandler(handler)
    if root.level > logging.INFO:
        root.setLevel(logging.INFO)

    old_argv = sys.argv[:]
    sys.argv = _build_argv(plugin.params or {}, plugin.__class__.__module__)
    result: Any = None
    error = ""
    try:
        with contextlib.redirect_stdout(stdout_buffer):
            result = check_callable()
    except SystemExit as exc:
        result = _system_exit_to_result(exc, _collected_output(stdout_buffer, log_buffer))
    except Exception as exc:
        error = str(exc)
    finally:
        sys.argv = old_argv
        root.removeHandler(handler)
        root.setLevel(previous_level)

    evidence = _collected_output(stdout_buffer, log_buffer)
    if error:
        evidence = "\n".join(part for part in (evidence, f"Exception: {error}") if part)

    return {
        "vulnerable": _normalize_result(result, evidence),
        "cve_id": getattr(plugin, "meta_cve_id", ""),
        "description": plugin.results.get("description") or getattr(plugin, "meta_poc_name", ""),
        "evidence": evidence[:4000],
    }


def _build_argv(params: dict[str, Any], module_name: str) -> list[str]:
    argv = [str(params.get("poc_id") or f"{module_name}.py")]
    serial = params.get("expected_usb_serial") or params.get("serial")
    if serial not in (None, ""):
        argv.extend(["--serial", str(serial)])
    return argv


def _system_exit_to_result(exc: SystemExit, evidence: str) -> bool:
    code = exc.code
    if code is None:
        code = 0
    elif isinstance(code, str):
        try:
            code = int(code)
        except Exception:
            code = 1
    if code == 0:
        return _looks_vulnerable(evidence)
    return False


def _collected_output(stdout_buffer: io.StringIO, log_buffer: io.StringIO) -> str:
    parts = [stdout_buffer.getvalue().strip(), log_buffer.getvalue().strip()]
    return "\n".join(part for part in parts if part)


def _normalize_result(result: Any, evidence: str) -> bool:
    if isinstance(result, dict):
        return bool(result.get("vulnerable"))
    if isinstance(result, bool):
        return result
    return _looks_vulnerable(evidence)


def _looks_vulnerable(evidence: str) -> bool:
    lowered = (evidence or "").lower()
    negative_markers = (
        "not vulnerable",
        "未检测到漏洞",
        "未发现漏洞",
        "not found",
        "no vulnerable",
    )
    if any(marker in lowered for marker in negative_markers):
        return False
    positive_markers = (
        "vulnerable",
        "漏洞存在",
        "存在漏洞",
        "风险：",
        "high risk",
        "critical risk",
        "found",
    )
    return any(marker in lowered for marker in positive_markers)

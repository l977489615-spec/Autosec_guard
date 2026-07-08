"""Helpers for local parser and local-kernel exploit stimuli."""
from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
from typing import Any, Callable


CRASH_MARKERS = (
    "asan",
    "heap",
    "overflow",
    "out-of-bounds",
    "use-after-free",
    "segmentation fault",
    "bus error",
    "abort",
    "crash",
    "core dumped",
)


def write_temp_sample(prefix: str, suffix: str, payload: bytes) -> str:
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
    return path


def write_temp_text(prefix: str, suffix: str, content: str) -> str:
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


def result_indicates_crash(returncode: int, stdout: str, stderr: str) -> bool:
    blob = f"{stdout}\n{stderr}".lower()
    return returncode < 0 or any(token in blob for token in CRASH_MARKERS)


def run_local_target(
    cmd: str,
    sample_path: str,
    *,
    timeout: float,
    arg_builder: Callable[[list[str], str], list[str]] | None = None,
) -> dict[str, Any]:
    argv = shlex.split(str(cmd))
    if arg_builder is None:
        argv.append(sample_path)
    else:
        argv = arg_builder(argv, sample_path)
    started = subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    stdout = started.stdout.decode("utf-8", errors="replace")
    stderr = started.stderr.decode("utf-8", errors="replace")
    return {
        "command": cmd,
        "argv": argv,
        "returncode": started.returncode,
        "stdout_excerpt": stdout[:1000],
        "stderr_excerpt": stderr[:1000],
        "vulnerable": result_indicates_crash(started.returncode, stdout, stderr),
    }


def build_local_sample_probe(
    plugin: Any,
    *,
    sample_param: str,
    command_params: tuple[str, ...],
    generated_sample: Callable[[], str],
    phenomenon: str,
    operator_action: str,
    arg_builder: Callable[[list[str], str], list[str]] | None = None,
) -> dict[str, Any]:
    supplied_sample = plugin.params.get(sample_param) or plugin.params.get("sample_path")
    sample = str(supplied_sample) if supplied_sample else generated_sample()
    cmd = next((plugin.params.get(name) for name in command_params if plugin.params.get(name)), "")
    evidence = {
        "ok": True,
        "sample_path": sample,
        "payload_bytes": os.path.getsize(sample),
        "sample_source": "operator_supplied" if supplied_sample else "generated_stimulus",
        "phenomenon": phenomenon,
        "requires_manual_review": True,
    }
    if not cmd:
        evidence["ok"] = False
        evidence["vulnerable"] = False
        evidence["execution_path_configured"] = False
        evidence["operator_action"] = operator_action
        evidence["reason"] = (
            "No executable validator/decoder command was provided. "
            "The script only generated a local stimulus artifact and did not "
            "exercise a real target-side parser, driver, service, or validator."
        )
        return evidence
    evidence["execution_path_configured"] = True
    evidence.update(
        run_local_target(
            str(cmd),
            sample,
            timeout=float(plugin.params.get("timeout", 15)),
            arg_builder=arg_builder,
        )
    )
    return evidence

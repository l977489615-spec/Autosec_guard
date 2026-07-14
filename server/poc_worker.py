import ast
import base64
import errno
import ipaddress
import json
import logging
import os
try:
    import resource
except ImportError:
    resource = None  # Windows: resource module unavailable
import shutil
import socket
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional
from poc_security import should_require_disruptive_approval

logger = logging.getLogger(__name__)


SERVER_DIR = Path(__file__).resolve().parent
if getattr(sys, "frozen", False):
    SERVER_DIR = Path(getattr(sys, "_MEIPASS"))
POCS_DIR = SERVER_DIR / "pocs"
POC_WORDLISTS_DIR = POCS_DIR / "wordlists"
SANDBOX_RUNNER = SERVER_DIR / "sandbox_runner.py"


MANUAL_REVIEW_FILENAME_KEYWORDS = {
    "keyfob",
    "key_fob",
    "gps_spoof",
    "tpms",
    "v2x_bsm",
    "mirror_hijack",
    "vehicle_ctrl",
    "unauth_vehicle",
    "keystroke_injection",
    "rf_replay",
    "replay_attack",
    "can_replay",
    "ecu_reset",
    "routing_activation",
}

# 仅当协议层结果无法由程序直接判定、需观察车端/射频/总线物理现象时才默认人工复核。
HARDWARE_REVIEW_PROTOCOLS = {"can", "uds", "obd", "rf", "sdr", "tpms", "v2x", "bluetooth", "ble"}
HARDWARE_PARAM_HINTS = {
    "can_interface", "can_bitrate", "bluetooth_mac", "bd_addr", "target_mac",
    "wifi_interface", "interface", "frequency", "usb_device_serial", "expected_usb_serial",
}

# CAN/UDS 中会影响车辆状态、需肉眼确认的动作类 PoC（被动嗅探/读内存等不在此列）。
MANUAL_REVIEW_CAN_KEYWORDS = {
    "replay",
    "message_injection",
    "ecu_reset",
    "routing_activation",
    "dos_flood",
}

MANUAL_REVIEW_EVIDENCE_KEYWORDS = {
    "requires manual",
    "manual confirmation",
    "operator confirmation",
    "operator confirmed",
    "observe the target",
    "observe vehicle",
    "physical effect",
    "vehicle unlock",
    "door lock",
    "visible response",
    "replay transmitted",
}


def _is_packaged_runtime() -> bool:
    return bool(
        getattr(sys, "frozen", False)
        or hasattr(sys, "__compiled__")
        or os.environ.get("NUITKA_ONEFILE_PARENT")
        or os.environ.get("PYINSTALLER_SAFE_MODE")
    )


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
        # 未指定目标 IP 时拒绝所有出站连接，防止 PoC 被用作扫描/攻击跳板
        return False

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


def _extract_security_profile_from_source(source_text: str, poc_name: str) -> dict:
    profile = {
        "poc_name": poc_name,
        "cve_id": "",
        "severity": "",
        "protocol": "",
        "target_os": [],
        "required_params": [],
        "profiles": [],
        "destructive_level": "Safe",
        "is_disruptive": False,
        "requires_operator_observation": None,
        "requires_manual_review": None,
        "capability_dependencies": [],
    }

    try:
        tree = ast.parse(source_text, filename=poc_name)
        metadata_keys = {
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
            "requires_operator_observation",
            "requires_manual_review",
            "meta_capability_dependencies",
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
                profile["profiles"] = class_meta.get("meta_profiles") or profile["profiles"]
                profile["destructive_level"] = class_meta.get("meta_destructive_level") or profile["destructive_level"]
                profile["is_disruptive"] = bool(class_meta.get("is_disruptive", profile["is_disruptive"]))
                profile["requires_operator_observation"] = class_meta.get("requires_operator_observation")
                profile["requires_manual_review"] = class_meta.get("requires_manual_review")
                profile["capability_dependencies"] = class_meta.get("meta_capability_dependencies") or []
                break
    except Exception as exc:
        profile["parse_error"] = str(exc)
    return profile


def _extract_security_profile(poc_path: str, poc_code: Optional[str] = None) -> dict:
    if poc_code is not None:
        return _extract_security_profile_from_source(poc_code, os.path.basename(poc_path))
    with open(poc_path, "r", encoding="utf-8") as handle:
        return _extract_security_profile_from_source(handle.read(), os.path.basename(poc_path))


def _requires_disruptive_approval(profile: dict, params: dict) -> bool:
    return should_require_disruptive_approval(profile, params)


def poc_requires_human_review(poc_filename: str, profile: dict, plugin_results: Optional[dict] = None) -> bool:
    """Return True only when operator observation is required to judge exploit effect.

    Network banner/login/log-leak style PoCs should auto-confirm via plugin_results.
    Physical/RF/CAN vehicle-effect PoCs may opt in explicitly or match narrow heuristics.
    """
    plugin_results = plugin_results or {}
    explicit = plugin_results.get("requires_human_review")
    if explicit is None:
        explicit = plugin_results.get("requires_manual_review")
    if explicit is None:
        explicit = plugin_results.get("manual_confirmation_required")
    if explicit in {False, "false", "False", "0", 0}:
        return False

    poc_path = str(poc_filename or "").replace("\\", "/").lower()
    name_text = " ".join([
        poc_path,
        str(profile.get("poc_name") or ""),
        str(profile.get("cve_id") or ""),
    ]).lower().replace("-", "_")

    # A descriptor-level decision is authoritative. In particular, explicit False
    # prevents protocol/name heuristics from creating unnecessary operator work.
    profile_explicit = profile.get("requires_operator_observation")
    if profile_explicit is None:
        profile_explicit = profile.get("requires_manual_review")
    if profile_explicit in {False, "false", "False", "0", 0}:
        return False

    protocol = str(profile.get("protocol") or "").strip().lower()
    required_params = {
        str(value).strip().lower() for value in (profile.get("required_params") or []) if str(value).strip()
    }
    capability_dependencies = {
        str(value).strip().lower() for value in (profile.get("capability_dependencies") or []) if str(value).strip()
    }
    hardware_dependent = (
        protocol in HARDWARE_REVIEW_PROTOCOLS
        or bool(required_params & HARDWARE_PARAM_HINTS)
        or bool(capability_dependencies & {"can", "sdr", "rf", "bluetooth", "ble", "usb", "vehicle"})
    )

    if not hardware_dependent:
        return False

    if explicit in {True, "true", "True", "1", 1}:
        return True

    if profile_explicit in {True, "true", "True", "1", 1}:
        return True

    # A machine-verifiable verdict is final unless the descriptor explicitly says
    # the physical effect itself must still be observed by an operator.
    if plugin_results.get("vulnerable") in (True, False):
        return False

    if poc_path.startswith("canbus/") or protocol in {"can", "uds", "obd"}:
        if any(keyword in name_text for keyword in MANUAL_REVIEW_CAN_KEYWORDS):
            return True

    if any(keyword in name_text for keyword in MANUAL_REVIEW_FILENAME_KEYWORDS):
        return True

    evidence_text = " ".join([
        str(plugin_results.get("evidence") or ""),
        str(plugin_results.get("details") or ""),
        str(plugin_results.get("description") or ""),
    ]).lower()
    if evidence_text and any(keyword in evidence_text for keyword in MANUAL_REVIEW_EVIDENCE_KEYWORDS):
        return True

    return False


def build_manual_review_prompt(poc_filename: str, profile: dict) -> dict:
    protocol = str(profile.get("protocol") or "").strip().lower()
    observations = [
        "观察目标是否出现业务状态变化、异常提示、重启、断连或可见物理动作。",
        "记录观察时间、现场条件、目标标识和证据文件路径。",
    ]
    if protocol in {"can", "uds", "obd"} or "can" in str(poc_filename).lower():
        observations = [
            "记录 CAN ID、帧类型、发送次数、网关/ECU 响应和车辆/台架可见变化。",
            "确认是否出现门锁、灯光、仪表、诊断会话或 ECU 状态变化。",
        ]
    elif protocol in {"rf", "sdr", "tpms"} or "keyfob" in str(poc_filename).lower():
        observations = [
            "确认是否出现车门解锁/闭锁、双闪、蜂鸣器、胎压状态或其他 RF 相关物理响应。",
            "记录频率、采样率、重放次数、车辆距离和现场安全状态。",
        ]
    elif protocol in {"bluetooth", "ble"} or "bt_" in str(poc_filename).lower():
        observations = [
            "确认蓝牙连接、配对状态、媒体/电话/HID 行为或目标服务是否发生变化。",
            "记录目标 MAC、通道/PSM、连接状态和用户可见现象。",
        ]

    return {
        "prompt": "该 PoC 的执行完成不等于漏洞利用成功，需要人工观察目标侧效果后给出最终判定。",
        "required_observations": observations,
        "verdict_options": [
            "confirmed_vulnerable",
            "confirmed_not_vulnerable",
            "inconclusive",
            "needs_retest",
        ],
    }


def apply_manual_review_state(
    result: dict,
    *,
    poc_filename: str,
    security_profile: dict,
    plugin_results: Optional[dict] = None,
) -> dict:
    plugin_results = plugin_results or {}
    evidence_value = (
        result.get("evidence")
        or plugin_results.get("evidence")
        or result.get("details")
        or plugin_results.get("details")
    )
    if isinstance(evidence_value, (dict, list)):
        evidence = json.dumps(evidence_value, ensure_ascii=False)
    else:
        evidence = str(evidence_value or "").strip()
    if evidence:
        result["evidence"] = evidence

    requires_review = poc_requires_human_review(poc_filename, security_profile, plugin_results)
    if not requires_review:
        result["requires_human_review"] = False
        result["manual_review"] = {"state": "not_required"}
        if not result.get("success"):
            result["verification_status"] = "execution_error"
            result["evidence_contract_valid"] = False
        elif result.get("vulnerable") is not True and result.get("vulnerable") is not False:
            result["vulnerable"] = None
            result["verification_status"] = "inconclusive"
            result["evidence_contract_valid"] = bool(evidence)
        elif not evidence:
            result["vulnerable"] = None
            result["verification_status"] = "invalid_result"
            result["evidence_contract_valid"] = False
            result["contract_error"] = "PoC completed without evidence; a confirmed verdict is not allowed."
        else:
            result["verification_status"] = (
                "auto_confirmed_vulnerable" if bool(result.get("vulnerable")) else "auto_confirmed_not_vulnerable"
            )
            result["evidence_contract_valid"] = True
        return result

    existing_verdict = (
        plugin_results.get("manual_verdict")
        or plugin_results.get("operator_verdict")
        or result.get("manual_verdict")
    )
    result["requires_human_review"] = True
    result["manual_review"] = {
        "state": "pending",
        "verdict": existing_verdict or "",
        **build_manual_review_prompt(poc_filename, security_profile),
    }

    if existing_verdict == "confirmed_vulnerable":
        if evidence:
            result["vulnerable"] = True
            result["verification_status"] = "manual_confirmed_vulnerable"
            result["manual_review"]["state"] = "completed"
            result["evidence_contract_valid"] = True
        else:
            result["vulnerable"] = None
            result["verification_status"] = "invalid_result"
            result["manual_review"]["state"] = "invalid_evidence"
            result["evidence_contract_valid"] = False
            result["contract_error"] = "Manual vulnerable verdict requires recorded evidence."
    elif existing_verdict == "confirmed_not_vulnerable":
        if evidence:
            result["vulnerable"] = False
            result["verification_status"] = "manual_confirmed_not_vulnerable"
            result["manual_review"]["state"] = "completed"
            result["evidence_contract_valid"] = True
        else:
            result["vulnerable"] = None
            result["verification_status"] = "invalid_result"
            result["manual_review"]["state"] = "invalid_evidence"
            result["evidence_contract_valid"] = False
            result["contract_error"] = "Manual not-vulnerable verdict requires recorded evidence."
    elif existing_verdict in {"inconclusive", "needs_retest"}:
        result["vulnerable"] = None
        result["verification_status"] = f"manual_{existing_verdict}"
        result["manual_review"]["state"] = "completed"
        result["evidence_contract_valid"] = bool(evidence)
    else:
        result["vulnerable"] = None
        result["verification_status"] = "pending_manual_review"
        result["evidence"] = evidence or "PoC executed; waiting for operator observation and verdict."
        result["evidence_contract_valid"] = False
    return result


def _build_sandbox_env(params: dict, allowed_hosts: Optional[List[str]] = None) -> dict:
    env = os.environ.copy()
    env["SANDBOX_CPU_SECONDS"] = str(params.get("sandbox_cpu_seconds", _parse_int_env("SANDBOX_CPU_SECONDS", 60)))
    env["SANDBOX_MEMORY_MB"] = str(params.get("sandbox_memory_mb", _parse_int_env("SANDBOX_MEMORY_MB", 256)))
    env["SANDBOX_OUTPUT_MB"] = str(params.get("sandbox_output_mb", _parse_int_env("SANDBOX_OUTPUT_MB", 8)))
    env["SANDBOX_NOFILE"] = str(params.get("sandbox_nofile", _parse_int_env("SANDBOX_NOFILE", 256)))
    env["SANDBOX_ALLOWED_HOSTS"] = ",".join(allowed_hosts or [])
    env["AUTOSEC_POC_WORDLIST_DIR"] = str(POC_WORDLISTS_DIR)
    return env


def _loads_last_json_object(raw_text: str) -> dict:
    text = (raw_text or "").strip()
    if not text:
        return {}

    decoder = json.JSONDecoder()
    idx = 0
    last_obj = None
    while idx < len(text):
        while idx < len(text) and text[idx].isspace():
            idx += 1
        if idx >= len(text):
            break
        try:
            obj, end = decoder.raw_decode(text, idx)
            if isinstance(obj, dict):
                last_obj = obj
            idx = end
        except json.JSONDecodeError:
            next_start = text.find("{", idx + 1)
            if next_start < 0:
                break
            idx = next_start
    if last_obj is None:
        raise ValueError("No JSON object found after result token")
    return last_obj


def _parse_plugin_result(stdout_text: str) -> tuple[list[str], dict]:
    parts = stdout_text.rsplit("===RESULT_TOKEN===", 1)
    logs_text = parts[0]
    result_json = parts[1].strip() if len(parts) > 1 else "{}"
    try:
        plugin_results = _loads_last_json_object(result_json)
    except Exception as exc:
        plugin_results = {"vulnerable": False, "error": f"Failed to parse result: {exc}", "raw": result_json}
    return logs_text.splitlines(), plugin_results


def _runtime_entrypoint() -> str:
    """
    Exhaustive search for the most reliable executable entrypoint.
    Prioritizes the stable host binary, then sys.executable, then system python3.
    """
    if _is_packaged_runtime():
        preferred_paths = [
            os.environ.get("NUITKA_ONEFILE_BINARY"),
            os.environ.get("AUTOSEC_WORKSTATION_EXECUTABLE"),
            os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else None,
            sys.executable,
        ]
        for candidate in preferred_paths:
            if candidate and os.path.isfile(candidate):
                return candidate

        sys_python = shutil.which("python3") or shutil.which("python")
        if sys_python:
            return sys_python

        return sys.executable
        
    return sys.executable


def _build_command(poc_path: str, params: dict, use_unbuffered: bool = False) -> list[str]:
    if _is_packaged_runtime():
        return [_runtime_entrypoint(), "--run-sandbox", poc_path, json.dumps(params)]
    runner_args = [str(SANDBOX_RUNNER), poc_path, json.dumps(params)]
    if use_unbuffered:
        return [_runtime_entrypoint(), "-u", *runner_args]
    return [_runtime_entrypoint(), *runner_args]


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
    poc_code: Optional[str] = None
    timeout_seconds: int = 60
    # 运行时由 iter_stream 填充，供 cancel() 使用
    _proc: Optional[subprocess.Popen] = None


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
        poc_code: Optional[str] = None,
    ) -> PocWorkerPlan:
        poc_filename = os.path.basename(poc_path)
        security_profile = _extract_security_profile(
            poc_path,
            poc_code=poc_code if poc_code and not os.path.exists(poc_path) else None,
        )
        allowed_hosts = []
        target_host = str(params.get('target_ip') or '').strip()
        if target_host:
            try:
                allowed_hosts.append(str(ipaddress.ip_address(target_host)))
            except ValueError:
                infos = socket.getaddrinfo(target_host, None, type=socket.SOCK_STREAM)
                allowed_hosts.extend(sorted({str(info[4][0]).split('%')[0] for info in infos}))
                params = dict(params)
                params['target_hostname'] = target_host
                params['target_ip'] = allowed_hosts[0]

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
            poc_code=poc_code,
            timeout_seconds=timeout_seconds,
        )

    def run_once(self, plan: PocWorkerPlan) -> dict:
        start_time = time.time()
        logs = []
        
        env_override = dict(plan.env)
        if plan.poc_code:
            env_override["AUTOSEC_POC_INLINE_CODE_B64"] = base64.b64encode(
                plan.poc_code.encode("utf-8")
            ).decode("ascii")
            env_override["AUTOSEC_POC_INLINE_NAME"] = plan.poc_filename

        try:
            logs.append(f"[*] Executing sandbox command: {' '.join(plan.command)}")
            proc = subprocess.Popen(
                plan.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env_override,
                start_new_session=True,
            )
            plan._proc = proc
            try:
                stdout_text, _ = proc.communicate(timeout=plan.timeout_seconds)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout_text, _ = proc.communicate()
                elapsed = round(time.time() - start_time, 2)
                p_logs, plugin_results = _parse_plugin_result(stdout_text or "")
                logs.extend(p_logs)
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

        except Exception as e:
            elapsed = round(time.time() - start_time, 2)
            logs.append(f"[-] Subprocess failure: {e}")
            return {
                "success": False,
                "logs": logs,
                "plugin_results": {"error": str(e)},
                "elapsed_seconds": elapsed,
                "trace_id": plan.trace_id,
            }
        elapsed = round(time.time() - start_time, 2)
        p_logs, plugin_results = _parse_plugin_result(stdout_text or "")
        logs.extend(p_logs)
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
        import select

        env_override = dict(plan.env)
        if plan.poc_code:
            env_override["AUTOSEC_POC_INLINE_CODE_B64"] = base64.b64encode(
                plan.poc_code.encode("utf-8")
            ).decode("ascii")
            env_override["AUTOSEC_POC_INLINE_NAME"] = plan.poc_filename
        proc = subprocess.Popen(
            _build_command(plan.poc_path, plan.params, use_unbuffered=True),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env_override,
            start_new_session=True,
        )
        plan._proc = proc  # 供 cancel() 调用

        result_chunks: list[str] = []
        collecting_result = False
        start_time = time.time()
        deadline = start_time + max(1, int(plan.timeout_seconds))

        def _emit_timeout_result() -> dict:
            elapsed = round(time.time() - start_time, 2)
            return {
                "type": "result",
                "success": False,
                "timeout": True,
                "vulnerable": False,
                "evidence": "",
                "cve_id": "",
                "elapsed_seconds": elapsed,
                "errors": [f"PoC execution exceeded {plan.timeout_seconds}s sandbox timeout"],
                "trace_id": plan.trace_id,
                "security_profile": plan.security_profile,
                "sandbox_profile": plan.sandbox_profile,
                "plugin_results": {"error": "sandbox_timeout"},
                "worker_mode": plan.worker_mode,
            }

        try:
            assert proc.stdout is not None
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    self.cancel(plan)
                    yield _emit_timeout_result()
                    return

                ready, _, _ = select.select([proc.stdout], [], [], min(1.0, remaining))
                if not ready:
                    if proc.poll() is not None:
                        break
                    continue

                line = proc.stdout.readline()
                if not line:
                    break

                if "===RESULT_TOKEN===" in line:
                    before, after = line.split("===RESULT_TOKEN===", 1)
                    if before.strip():
                        yield {"type": "log", "message": before.strip()}
                    collecting_result = True
                    if after.strip():
                        result_chunks.append(after)
                    continue

                if collecting_result:
                    result_chunks.append(line)
                else:
                    yield {"type": "log", "message": line.strip()}

            try:
                proc.wait(timeout=max(0.1, deadline - time.time()))
            except subprocess.TimeoutExpired:
                self.cancel(plan)
                yield _emit_timeout_result()
                return

            try:
                result_json = "".join(result_chunks)
                plugin_results = _loads_last_json_object(result_json) if result_json.strip() else {}
            except Exception as exc:
                result_json = "".join(result_chunks)
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
            logger.error(f"PoC stream error [{plan.poc_filename}]: {exc}")
            yield {
                "type": "result",
                "success": False,
                "errors": [str(exc)],
                "trace_id": plan.trace_id,
                "security_profile": plan.security_profile,
                "sandbox_profile": plan.sandbox_profile,
                "worker_mode": plan.worker_mode,
            }


    def cancel(self, plan: "PocWorkerPlan") -> None:
        """终止关联的 PoC 子进程（客户端断连时调用）。"""
        proc = getattr(plan, "_proc", None)
        if proc is None or proc.poll() is not None:
            return
        try:
            import signal, os as _os
            _os.killpg(_os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def get_poc_worker(mode: Optional[str] = None):
    worker_mode = (mode or os.environ.get("AUTOSEC_POC_WORKER_MODE", "local_sandbox")).strip().lower()
    # Future extension point: docker, k8s, remote queue workers.
    return LocalSandboxPocWorker(worker_mode=worker_mode)

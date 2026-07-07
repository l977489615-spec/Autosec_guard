import sys
import json
import os
import base64
import importlib.util
import time
import traceback
import logging
import errno
import ipaddress
try:
    import resource as _resource_mod
    _HAS_RESOURCE = True
except ImportError:
    _resource_mod = None  # type: ignore[assignment,misc]
    _HAS_RESOURCE = False
import socket
from pathlib import Path
from types import ModuleType
from typing import Any, Tuple, Union, cast

from poc_registry import get_poc_code

_SocketAddress = Union[tuple[Any, ...], str, bytes]


EMBEDDED_SUPPORT_MODULES = {
    "iv_plugin_base": "iv_plugin_base.py",
    "can_bus_utils": "canbus/can_bus_utils.py",
}


def _parse_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    try:
        return int(raw if raw is not None else default)
    except Exception:
        return int(default)


def _apply_resource_limits():
    if not _HAS_RESOURCE or _resource_mod is None:
        return
    cpu_seconds = _parse_int_env("SANDBOX_CPU_SECONDS", 60)
    memory_mb = _parse_int_env("SANDBOX_MEMORY_MB", 256)
    output_mb = _parse_int_env("SANDBOX_OUTPUT_MB", 8)
    nofile_count = _parse_int_env("SANDBOX_NOFILE", 256)

    limits = [
        (getattr(_resource_mod, "RLIMIT_CPU", None), cpu_seconds),
        (getattr(_resource_mod, "RLIMIT_AS", None), memory_mb * 1024 * 1024),
        (getattr(_resource_mod, "RLIMIT_FSIZE", None), output_mb * 1024 * 1024),
        (getattr(_resource_mod, "RLIMIT_NOFILE", None), nofile_count),
    ]

    for limit_name, value in limits:
        if limit_name is None:
            continue
        try:
            _resource_mod.setrlimit(limit_name, (value, value))
        except Exception:
            continue


def _allowed_hosts_from_env():
    hosts = set()
    raw_hosts = os.environ.get("SANDBOX_ALLOWED_HOSTS", "")
    for item in raw_hosts.split(","):
        item = item.strip()
        if item:
            hosts.add(item)
    return hosts


def _is_allowed_destination(host, allowed_hosts):
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


def _install_socket_guard():
    allowed_hosts = _allowed_hosts_from_env()
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_create_connection = socket.create_connection

    def guarded_connect(self, address: _SocketAddress):
        host = address[0] if isinstance(address, tuple) and address else address
        if not _is_allowed_destination(host, allowed_hosts):
            raise ConnectionRefusedError(f"sandbox network allowlist blocked destination {host}")
        return original_connect(self, cast(Any, address))

    def guarded_connect_ex(self, address: _SocketAddress):
        host = address[0] if isinstance(address, tuple) and address else address
        if not _is_allowed_destination(host, allowed_hosts):
            return errno.ECONNREFUSED
        return original_connect_ex(self, cast(Any, address))

    def guarded_create_connection(address: _SocketAddress, timeout=None, source_address=None):
        host = address[0] if isinstance(address, tuple) and address else address
        if not _is_allowed_destination(host, allowed_hosts):
            raise ConnectionRefusedError(f"sandbox network allowlist blocked destination {host}")
        return original_create_connection(cast(Any, address), timeout=timeout, source_address=source_address)

    socket.socket.connect = guarded_connect  # type: ignore[method-assign,assignment]
    socket.socket.connect_ex = guarded_connect_ex  # type: ignore[method-assign,assignment]
    socket.create_connection = guarded_create_connection  # type: ignore[assignment]


def _load_module_from_source(module_name, source_text, source_path):
    module = ModuleType(module_name)
    module.__file__ = source_path
    sys.modules[module_name] = module
    exec(compile(source_text, source_path, "exec"), module.__dict__)
    return module


def _inject_params_env(params):
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


def _build_script_argv(poc_filename, params):
    """仅注入各脚本已声明的 CLI 参数；target_ip 统一走 AUTOSEC_TARGET_IP 环境变量。"""
    argv = [poc_filename]
    serial = params.get("expected_usb_serial") or params.get("serial")
    if serial not in (None, ""):
        argv.extend(["--serial", str(serial)])
    return argv


def _run_standalone_script(module, poc_filename, params):
    import contextlib
    import io
    import logging

    _inject_params_env(params)
    argv = _build_script_argv(poc_filename, params)
    log_buffer = io.StringIO()
    stdout_buffer = io.StringIO()
    handler = logging.StreamHandler(log_buffer)
    handler.setLevel(logging.INFO)
    root = logging.getLogger()
    previous_level = root.level
    root.addHandler(handler)
    if root.level > logging.INFO:
        root.setLevel(logging.INFO)

    old_argv = sys.argv[:]
    old_cwd = os.getcwd()
    sys.argv = argv
    vulnerable = False
    evidence = ""
    error = ""
    def collected_output():
        parts = [stdout_buffer.getvalue().strip(), log_buffer.getvalue().strip()]
        return "\n".join(part for part in parts if part)

    try:
        module_file = getattr(module, "__file__", "")
        module_dir = os.path.dirname(module_file) if module_file else ""
        if module_dir:
            os.chdir(module_dir)
        if not hasattr(module, "main") or not callable(module.main):
            return False, "", "No main() entrypoint found"
        with contextlib.redirect_stdout(stdout_buffer):
            result = module.main()
        if result is True:
            vulnerable = True
            evidence = collected_output() or "main() returned True"
        elif result is False:
            vulnerable = False
            evidence = collected_output() or "main() returned False"
        else:
            vulnerable = False
            evidence = collected_output() or "main() completed"
    except SystemExit as exc:
        code = exc.code
        if code is None:
            code = 0
        elif isinstance(code, str):
            try:
                code = int(code)
            except Exception:
                code = 1
        vulnerable = False
        evidence = collected_output() or f"exit code {code}"
        if code not in (0, 1):
            error = f"script exited with code {code}"
    except Exception as exc:
        error = str(exc)
        evidence = collected_output()
    finally:
        sys.argv = old_argv
        os.chdir(old_cwd)
        root.removeHandler(handler)
        root.setLevel(previous_level)

    if error:
        return False, evidence, error
    return vulnerable, evidence[:4000], ""


def _ensure_embedded_support_modules(pocs_dir):
    for module_name, registry_key in EMBEDDED_SUPPORT_MODULES.items():
        if module_name in sys.modules:
            continue

        module_path = pocs_dir / registry_key
        if module_path.exists():
            spec = importlib.util.spec_from_file_location(module_name, str(module_path))
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            continue

        source_text, normalized_name = get_poc_code(registry_key)
        if not source_text:
            continue
        _load_module_from_source(module_name, source_text, normalized_name or registry_key)

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 sandbox_runner.py <poc_path> <params_json>")
        sys.exit(1)

    poc_path = sys.argv[1]
    inline_code_b64 = os.environ.get("AUTOSEC_POC_INLINE_CODE_B64", "")
    try:
        params = json.loads(sys.argv[2])
    except Exception as e:
        print(f"Error parsing params: {e}")
        sys.exit(1)

    # Resolve possible locations for pocs/ and iv_plugin_base.py
    current_dir = Path(__file__).resolve().parent
    pocs_dir = current_dir / "pocs"
    if not pocs_dir.exists():
        # Fallback if runner is already inside the pocs directory or in a sibling folder
        pocs_dir = current_dir if (current_dir / "iv_plugin_base.py").exists() else current_dir.parent / "pocs"
    
    poc_filename = os.environ.get("AUTOSEC_POC_INLINE_NAME") or os.path.basename(poc_path)
    poc_dir = os.path.dirname(poc_path)
    _apply_resource_limits()
    _install_socket_guard()
    
    # Ensure iv_plugin_base can be found
    sys.path.insert(0, poc_dir)
    sys.path.insert(0, str(pocs_dir))

    try:
        module_name = poc_filename.replace('.py', '')
        _ensure_embedded_support_modules(pocs_dir)
        if inline_code_b64:
            inline_code = base64.b64decode(inline_code_b64).decode("utf-8")
            module = _load_module_from_source(module_name, inline_code, poc_path)
        else:
            spec = importlib.util.spec_from_file_location(module_name, poc_path)
            if spec is None or spec.loader is None:
                print(json.dumps({"error": f"Unable to load PoC module from {poc_path}"}))
                sys.exit(1)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

        plugin_class = None
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and attr_name not in ['IVIVulnerabilityPlugin'] and hasattr(attr, 'run_verify'):
                plugin_class = attr
                break

        if not plugin_class:
            vulnerable, evidence, script_error = _run_standalone_script(module, poc_filename, params)
            if script_error and not evidence:
                print(json.dumps({"error": script_error}))
                sys.exit(1)
            payload = {
                "vulnerable": vulnerable,
                "evidence": evidence,
                "cve_id": "",
                "poc_id": poc_filename,
            }
            if script_error:
                payload["error"] = script_error
            print("===RESULT_TOKEN===")
            print(json.dumps(payload))
            sys.exit(0 if not script_error else 1)

        plugin = plugin_class(params)
        
        # Capture print output and pass on logs
        plugin.run_verify()
        
        # Output result token at the end so parent can parse it
        print("===RESULT_TOKEN===")
        print(json.dumps({
            "vulnerable": plugin.results.get("vulnerable", False),
            "evidence": plugin.results.get("evidence", ""),
            "cve_id": getattr(plugin, 'meta_cve_id', plugin.results.get("cve_id", "")),
            "poc_id": poc_filename
        }))

    except Exception as e:
        print("===RESULT_TOKEN===")
        print(json.dumps({"error": str(e), "traceback": traceback.format_exc()}))
        sys.exit(1)

if __name__ == "__main__":
    main()

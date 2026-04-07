import sys
import json
import os
import importlib.util
import time
import traceback
import logging
import errno
import ipaddress
import resource
import socket


def _parse_int_env(name, default):
    try:
        return int(os.environ.get(name, default))
    except Exception:
        return int(default)


def _apply_resource_limits():
    cpu_seconds = _parse_int_env("SANDBOX_CPU_SECONDS", 60)
    memory_mb = _parse_int_env("SANDBOX_MEMORY_MB", 256)
    output_mb = _parse_int_env("SANDBOX_OUTPUT_MB", 8)
    nofile_count = _parse_int_env("SANDBOX_NOFILE", 256)

    limits = [
        (getattr(resource, "RLIMIT_CPU", None), cpu_seconds),
        (getattr(resource, "RLIMIT_AS", None), memory_mb * 1024 * 1024),
        (getattr(resource, "RLIMIT_FSIZE", None), output_mb * 1024 * 1024),
        (getattr(resource, "RLIMIT_NOFILE", None), nofile_count),
    ]

    for limit_name, value in limits:
        if limit_name is None:
            continue
        try:
            resource.setrlimit(limit_name, (value, value))
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

    def guarded_connect(self, address):
        host = address[0] if isinstance(address, (tuple, list)) and address else address
        if not _is_allowed_destination(host, allowed_hosts):
            raise ConnectionRefusedError(f"sandbox network allowlist blocked destination {host}")
        return original_connect(self, address)

    def guarded_connect_ex(self, address):
        host = address[0] if isinstance(address, (tuple, list)) and address else address
        if not _is_allowed_destination(host, allowed_hosts):
            return errno.ECONNREFUSED
        return original_connect_ex(self, address)

    def guarded_create_connection(address, timeout=None, source_address=None):
        host = address[0] if isinstance(address, (tuple, list)) and address else address
        if not _is_allowed_destination(host, allowed_hosts):
            raise ConnectionRefusedError(f"sandbox network allowlist blocked destination {host}")
        return original_create_connection(address, timeout=timeout, source_address=source_address)

    socket.socket.connect = guarded_connect
    socket.socket.connect_ex = guarded_connect_ex
    socket.create_connection = guarded_create_connection

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 sandbox_runner.py <poc_path> <params_json>")
        sys.exit(1)

    poc_path = sys.argv[1]
    try:
        params = json.loads(sys.argv[2])
    except Exception as e:
        print(f"Error parsing params: {e}")
        sys.exit(1)

    poc_filename = os.path.basename(poc_path)
    poc_dir = os.path.dirname(poc_path)
    _apply_resource_limits()
    _install_socket_guard()
    
    # Ensure iv_plugin_base can be found
    sys.path.insert(0, poc_dir)
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'pocs'))

    try:
        spec = importlib.util.spec_from_file_location(poc_filename.replace('.py', ''), poc_path)
        module = importlib.util.module_from_spec(spec)
        
        # Load iv_plugin_base explicitly just in case
        base_path = os.path.join(os.path.dirname(__file__), 'pocs', 'iv_plugin_base.py')
        if os.path.exists(base_path) and 'iv_plugin_base' not in sys.modules:
            base_spec = importlib.util.spec_from_file_location('iv_plugin_base', base_path)
            base_module = importlib.util.module_from_spec(base_spec)
            sys.modules['iv_plugin_base'] = base_module
            base_spec.loader.exec_module(base_module)

        spec.loader.exec_module(module)

        plugin_class = None
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and attr_name not in ['IVIVulnerabilityPlugin'] and hasattr(attr, 'run_verify'):
                plugin_class = attr
                break

        if not plugin_class:
            print(json.dumps({"error": "No valid plugin class found"}))
            sys.exit(1)

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
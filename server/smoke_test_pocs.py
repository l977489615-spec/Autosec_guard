#!/usr/bin/env python3
import json
from pathlib import Path

from poc_worker import SERVER_DIR, get_poc_worker


CASES = [
    {
        "name": "icmp-host-discovery",
        "path": "pocs/reconnaissance/01_ICMP_Host_Discovery.py",
        "params": {"target_ip": "127.0.0.1"},
    },
    {
        "name": "ssh-service",
        "path": "pocs/network/03_SSH_Service.py",
        "params": {"target_ip": "127.0.0.1"},
    },
    {
        "name": "carplay-overflow",
        "path": "pocs/application/03_CarPlay_Stack_Overflow.py",
        "params": {"target_ip": "127.0.0.1"},
    },
    {
        "name": "can-injection",
        "path": "pocs/canbus/02_CAN_Message_Injection.py",
        "params": {"can_interface": "vcan0"},
    },
    {
        "name": "bt-hfp-overflow",
        "path": "pocs/wireless/09_BT_HFP_AT_Overflow.py",
        "params": {"target_mac": "00:11:22:33:44:55"},
    },
    {
        "name": "gps-spoofing",
        "path": "pocs/advanced/03_GPS_Spoofing.py",
        "params": {"frequency": "1575420000"},
    },
]


def run_case(worker, case: dict) -> dict:
    poc_path = str((SERVER_DIR / case["path"]).resolve())
    plan = worker.prepare(
        poc_path,
        dict(case["params"]),
        trace_id=f"smoke-{case['name']}",
        session_id="smoke-test",
        timeout_seconds=20,
    )
    result = worker.run_once(plan)
    plugin_results = result.get("plugin_results", {})
    has_result_shape = isinstance(plugin_results.get("vulnerable"), bool)
    passed = result.get("returncode") == 0 and has_result_shape and "error" not in plugin_results
    return {
        "name": case["name"],
        "path": case["path"],
        "passed": passed,
        "returncode": result.get("returncode"),
        "plugin_results": plugin_results,
        "elapsed_seconds": result.get("elapsed_seconds"),
    }


def main() -> int:
    worker = get_poc_worker()
    results = [run_case(worker, case) for case in CASES]
    failed = [item for item in results if not item["passed"]]
    output = {
        "case_count": len(results),
        "passed_count": len(results) - len(failed),
        "failed_count": len(failed),
        "cases": results,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

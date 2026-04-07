#!/usr/bin/env python3
import ast
import json
from collections import Counter, defaultdict
from pathlib import Path


SERVER_DIR = Path(__file__).resolve().parent
POCS_DIR = SERVER_DIR / "pocs"
BASE_FILE = POCS_DIR / "iv_plugin_base.py"


BASE_KNOWN_ATTRS = {
    "target_ip",
    "target_port",
    "interface",
    "timeout",
    "params",
    "logger",
    "results",
    "create_connection",
    "run_verify",
    "check_prerequisites",
    "exploit",
    "get_report",
    "_print_final_verdict",
}

SAFE_GLOBAL_NAMES = {"sys", "int", "str", "float", "bool", "dict", "list"}

INPUT_TOKENS = [
    "target_ip",
    "target_port",
    "interface",
    "can_interface",
    "bd_addr",
    "target_mac",
    "client_mac",
    "ssid",
    "bssid",
    "frequency",
    "rf_freq",
]

DEPENDENCY_MAP = {
    "paramiko": "paramiko",
    "requests": "requests",
    "scapy": "scapy",
    "can": "python-can",
    "bluetooth": "pybluez/pybluez2",
    "paho.mqtt": "paho-mqtt",
    "someip": "python-someip",
    "udsoncan": "udsoncan",
}

HARDWARE_HINTS = {
    "pcan": "PCAN/CAN adapter",
    "socketcan": "SocketCAN interface",
    "hackrf": "HackRF SDR",
    "bluetooth": "Bluetooth adapter/stack",
    "scapy": "Monitor-mode Wi-Fi adapter",
    "can_interface": "CAN interface",
    "interface": "Dedicated network/radio interface",
}


def _iter_poc_files() -> list[Path]:
    files = []
    for path in sorted(POCS_DIR.rglob("*.py")):
        if ".venv" in path.parts or path == BASE_FILE:
            continue
        if path.name == "99_Dynamic_0Day.py":
            continue
        files.append(path)
    return files


def _load_requirements() -> set[str]:
    req_file = SERVER_DIR / "requirements.txt"
    reqs = set()
    for raw_line in req_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        reqs.add(line.split("==")[0].split(">=")[0].strip().lower())
    return reqs


def _line_numbers(text: str, needle: str) -> list[int]:
    lines = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            lines.append(idx)
    return lines


def _extract_main_block(tree: ast.Module) -> ast.If | None:
    for node in tree.body:
        if isinstance(node, ast.If):
            src = ast.get_source_segment(ast.unparse(tree) if hasattr(ast, "unparse") else "", node)
            if src and "__name__" in src and "__main__" in src:
                return node
            if (
                isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name)
                and node.test.left.id == "__name__"
            ):
                return node
    return None


def _discover_dependency_gaps(text: str, requirements: set[str]) -> list[str]:
    gaps = []
    lowered = text.lower()
    for mod, package in DEPENDENCY_MAP.items():
        mod_token = f"import {mod}"
        from_token = f"from {mod} "
        if mod_token in lowered or from_token in lowered:
            package_name = package.split("/")[0].lower()
            if package_name not in requirements:
                gaps.append(package)
    return sorted(set(gaps))


def _discover_hardware_hints(text: str) -> list[str]:
    lowered = text.lower()
    hits = []
    for token, label in HARDWARE_HINTS.items():
        if token in lowered:
            hits.append(label)
    return sorted(set(hits))


def _extract_class_info(tree: ast.Module, text: str) -> dict:
    info = {
        "class_name": None,
        "meta": {},
        "has_check_prerequisites": False,
        "has_exploit": False,
        "has_run_verify_override": False,
        "writes_vulnerable": False,
        "writes_evidence": False,
        "returns_vulnerable": False,
        "returns_evidence": False,
        "suspicious_attrs": [],
    }

    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue

        info["class_name"] = node.name
        init_sets = set()
        uses_attrs = set()

        for item in node.body:
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name) and (
                        target.id.startswith("meta_") or target.id == "is_disruptive"
                    ):
                        try:
                            info["meta"][target.id] = ast.literal_eval(item.value)
                        except Exception:
                            info["meta"][target.id] = "<dynamic>"

            if isinstance(item, ast.FunctionDef) and item.name == "__init__":
                for sub in ast.walk(item):
                    if isinstance(sub, ast.Assign):
                        for target in sub.targets:
                            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
                                init_sets.add(target.attr)

            if isinstance(item, ast.FunctionDef) and item.name == "check_prerequisites":
                info["has_check_prerequisites"] = True
            if isinstance(item, ast.FunctionDef) and item.name == "exploit":
                info["has_exploit"] = True
            if isinstance(item, ast.FunctionDef) and item.name == "run_verify":
                info["has_run_verify_override"] = True

            if isinstance(item, ast.FunctionDef):
                for sub in ast.walk(item):
                    if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) and sub.value.id == "self":
                        uses_attrs.add(sub.attr)

        info["writes_vulnerable"] = (
            "self.results['vulnerable']" in text or 'self.results["vulnerable"]' in text
        )
        info["writes_evidence"] = (
            "self.results['evidence']" in text or 'self.results["evidence"]' in text
        )
        info["returns_vulnerable"] = '"vulnerable"' in text or "'vulnerable'" in text
        info["returns_evidence"] = (
            '"evidence"' in text
            or "'evidence'" in text
            or '"details"' in text
            or "'details'" in text
        )
        info["suspicious_attrs"] = sorted(
            attr
            for attr in uses_attrs
            if attr not in BASE_KNOWN_ATTRS and attr not in init_sets and not attr.startswith("meta_")
        )
        return info

    return info


def _extract_main_issues(text: str, tree: ast.Module, class_name: str | None) -> dict:
    issues = {"undefined_names": []}
    if not class_name:
        return issues

    main_block = None
    for node in tree.body:
        if not isinstance(node, ast.If):
            continue
        segment = ast.get_source_segment(text, node) or ""
        if "__name__" in segment and "__main__" in segment:
            main_block = node
            break

    if main_block is None:
        return issues

    assigned = set()
    for stmt in main_block.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    assigned.add(target.id)

        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id == class_name:
                for arg in sub.args:
                    for name_node in ast.walk(arg):
                        if isinstance(name_node, ast.Name) and name_node.id not in assigned and name_node.id not in SAFE_GLOBAL_NAMES | {class_name}:
                            issues["undefined_names"].append(name_node.id)

    issues["undefined_names"] = sorted(set(issues["undefined_names"]))
    return issues


def _expected_required_params(text: str) -> list[str]:
    lowered = text.lower()
    return [token for token in INPUT_TOKENS if token in lowered]


def _score(record: dict) -> str:
    blockers = 0
    warnings = 0

    if record["main_issues"]["undefined_names"]:
        blockers += 1
    if record["expected_params"] and not record["meta_required_params"]:
        warnings += 1
    has_result_path = record["writes_vulnerable"] or record["returns_vulnerable"]
    if not has_result_path:
        blockers += 1
    if record["missing_dependencies"]:
        warnings += 1
    if record["hardware_hints"]:
        warnings += 1

    if blockers >= 1:
        return "red"
    if warnings >= 2:
        return "yellow"
    return "green"


def audit() -> dict:
    requirements = _load_requirements()
    files = _iter_poc_files()
    records = []
    summary = Counter()
    by_category = defaultdict(Counter)

    for path in files:
        text = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(text, filename=str(path))
        class_info = _extract_class_info(tree, text)
        main_issues = _extract_main_issues(text, tree, class_info["class_name"])
        meta_required_params = class_info["meta"].get("meta_required_params") or []
        expected_params = _expected_required_params(text)

        record = {
            "file": str(path.relative_to(SERVER_DIR)),
            "category": path.parent.name,
            "name": class_info["meta"].get("meta_poc_name") or path.stem,
            "meta_required_params": meta_required_params,
            "expected_params": expected_params,
            "writes_vulnerable": class_info["writes_vulnerable"],
            "writes_evidence": class_info["writes_evidence"],
            "returns_vulnerable": class_info["returns_vulnerable"],
            "returns_evidence": class_info["returns_evidence"],
            "has_check_prerequisites": class_info["has_check_prerequisites"],
            "has_exploit": class_info["has_exploit"],
            "missing_dependencies": _discover_dependency_gaps(text, requirements),
            "hardware_hints": _discover_hardware_hints(text),
            "main_issues": main_issues,
            "suspicious_attrs": class_info["suspicious_attrs"],
            "line_refs": {
                "meta_required_params": _line_numbers(text, "meta_required_params"),
                "writes_vulnerable": _line_numbers(text, 'self.results["vulnerable"]')
                + _line_numbers(text, "self.results['vulnerable']"),
                "main_block": _line_numbers(text, 'if __name__ == "__main__":')
                + _line_numbers(text, "if __name__ == '__main__':"),
            },
        }
        record["status"] = _score(record)
        records.append(record)
        summary[record["status"]] += 1
        by_category[record["category"]][record["status"]] += 1

    return {
        "summary": {
            "total": len(records),
            "green": summary["green"],
            "yellow": summary["yellow"],
            "red": summary["red"],
        },
        "by_category": {key: dict(value) for key, value in sorted(by_category.items())},
        "records": records,
    }


def main() -> int:
    report = audit()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

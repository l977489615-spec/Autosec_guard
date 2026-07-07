"""统一实验运行器：动态加载 pocN_*.py 并规范化结果。"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import time
import traceback
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

NEW_POC_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = NEW_POC_ROOT / "experiment_manifest.json"
POC_FILE_PATTERN = re.compile(r"^poc(\d+)_([A-Za-z0-9_]+)\.py$")


@dataclass
class ExperimentResult:
    poc_id: str
    filename: str
    title: str
    vulnerable: bool | None
    status: str  # ok | error | skipped | manual
    duration_ms: int
    message: str = ""
    category: str = "general"
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _load_manual_cases() -> list[dict[str, Any]]:
    if not MANIFEST_PATH.is_file():
        return []
    try:
        payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return [item for item in payload.get("manual_cases", []) if item.get("manual")]


def discover_pocs(include_manual: bool = False) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for path in sorted(NEW_POC_ROOT.glob("poc*.py")):
        match = POC_FILE_PATTERN.match(path.name)
        if not match:
            continue
        spec = _load_module(path)
        title = getattr(spec, "POC_TAG", None) or getattr(spec, "TAG", path.stem)
        items.append(
            {
                "poc_id": path.stem,
                "filename": path.name,
                "number": int(match.group(1)),
                "title": str(title).strip(),
                "category": _infer_category(path.name, str(title)),
                "automated": True,
            }
        )
    if include_manual:
        for case in _load_manual_cases():
            items.append(case)
    return sorted(items, key=lambda item: (item.get("number", 9999), item.get("poc_id", "")))


def _infer_category(filename: str, title: str) -> str:
    text = f"{filename} {title}".lower()
    if "can" in text:
        return "can_manual"
    if any(token in text for text in (text,) for token in ("webview", "manifest", "export", "provider", "activity", "service", "broadcast")):
        return "app_manifest"
    if any(token in text for token in ("lib", "openssl", "libpng", "libav", "libupnp", "libjpeg")):
        return "native_library"
    if any(token in text for token in ("adb", "ssh", "telnet", "ftp", "http", "hotspot", "webindex")):
        return "hotspot_network"
    if any(token in text for token in ("selinux", "aslr", "stack", "zygote", "procfs", "syslog", "db")):
        return "system_hardening"
    if "bluetooth" in text:
        return "wireless"
    return "general"


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _normalize_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "vulnerable", "fail"}:
            return True
        if lowered in {"false", "0", "no", "clean", "secure", "pass"}:
            return False
    return None


def run_poc(
    poc_id_or_file: str,
    *,
    argv: Iterable[str] | None = None,
    workdir: Path | None = None,
) -> ExperimentResult:
    workdir = workdir or NEW_POC_ROOT
    target = Path(poc_id_or_file)
    if not target.suffix:
        target = NEW_POC_ROOT / f"{poc_id_or_file}.py"
    if not target.is_file():
        target = NEW_POC_ROOT / poc_id_or_file
    if not target.is_file():
        manual = next((item for item in _load_manual_cases() if item.get("poc_id") == poc_id_or_file), None)
        if manual:
            return ExperimentResult(
                poc_id=manual["poc_id"],
                filename=manual.get("artifact", ""),
                title=manual.get("title", manual["poc_id"]),
                vulnerable=None,
                status="manual",
                duration_ms=0,
                message=manual.get("instructions", "需人工在 CAN 工具中注入并观察。"),
                category="can_manual",
                meta=manual,
            )
        raise FileNotFoundError(f"PoC not found: {poc_id_or_file}")

    title = target.stem
    started = time.time()
    old_argv = sys.argv[:]
    old_cwd = os.getcwd()
    try:
        os.chdir(workdir)
        sys.argv = [str(target), *(list(argv) if argv is not None else [])]
        module = _load_module(target)
        title = str(getattr(module, "POC_TAG", None) or getattr(module, "TAG", target.stem)).strip()
        if not hasattr(module, "main"):
            raise RuntimeError(f"{target.name} 缺少 main()，不符合实验 PoC 约定。")
        raw = module.main()
        vulnerable = _normalize_bool(raw)
        status = "ok"
        message = "main() 执行完成"
        if vulnerable is True:
            message = "检出风险"
        elif vulnerable is False:
            message = "未检出风险"
        elif vulnerable is None:
            message = "main() 未返回布尔值，视为 inconclusive"
            status = "skipped"
    except Exception as exc:
        vulnerable = None
        status = "error"
        message = f"{exc}\n{traceback.format_exc(limit=2)}"
    finally:
        sys.argv = old_argv
        try:
            os.chdir(old_cwd)
        except OSError:
            pass

    duration_ms = int((time.time() - started) * 1000)
    return ExperimentResult(
        poc_id=target.stem,
        filename=target.name,
        title=title,
        vulnerable=vulnerable,
        status=status,
        duration_ms=duration_ms,
        message=message.strip(),
        category=_infer_category(target.name, title),
    )


def run_batch(
    poc_ids: Iterable[str] | None = None,
    *,
    workdir: Path | None = None,
    stop_on_error: bool = False,
) -> list[ExperimentResult]:
    selected = list(poc_ids) if poc_ids else [item["poc_id"] for item in discover_pocs()]
    results: list[ExperimentResult] = []
    for poc_id in selected:
        try:
            result = run_poc(poc_id, workdir=workdir)
        except FileNotFoundError as exc:
            result = ExperimentResult(
                poc_id=poc_id,
                filename="",
                title=poc_id,
                vulnerable=None,
                status="error",
                duration_ms=0,
                message=str(exc),
            )
        results.append(result)
        if stop_on_error and result.status == "error":
            break
    return results

import os

from poc_registry import get_poc_code, list_builtin_pocs
from security_utils import safe_resolve_within


SUPPORT_MODULES = {
    "iv_plugin_base.py",
    "poc_runtime_adapter.py",
    "advisory_audit_core.py",
    "active_validation_core.py",
    "probe_utils.py",
    "local_exp_stimulus.py",
    "wireless/wireless_cve_audit.py",
    "wireless_cve_audit.py",
    "canbus/can_bus_utils.py",
    "can_bus_utils.py",
}
NON_POC_SCRIPTS = {"run_experiment.py", "diagnostic_upnp.py", "deep_diagnostic.py"}


def is_executable_poc_name(name: str) -> bool:
    normalized = str(name or "").replace("\\", "/").lstrip("./")
    basename = os.path.basename(normalized)
    parts = [part for part in normalized.split("/") if part]
    if any(part.startswith("_") for part in parts[:-1]):
        return False
    return (
        normalized.endswith(".py")
        and not basename.startswith("__")
        and basename not in SUPPORT_MODULES
        and basename not in NON_POC_SCRIPTS
        and normalized not in SUPPORT_MODULES
    )


def resolve_poc_path(pocs_dir: str, poc_filename: str) -> tuple[str | None, str | None]:
    if not poc_filename:
        return None, None

    # 安全校验：只允许 .py 且必须解析到 pocs_dir 之内（防路径穿越）。
    # 拒绝 ../、绝对路径、以及非 PoC 命名（如 __init__.py、支持模块）。
    if not is_executable_poc_name(poc_filename):
        # 仍可能是内建 PoC（不落盘），交由 builtin 分支判断
        builtin_code, normalized = get_poc_code(poc_filename)
        if builtin_code and normalized and is_executable_poc_name(normalized):
            safe_builtin = safe_resolve_within(pocs_dir, normalized)
            if safe_builtin:
                return safe_builtin, normalized
        return None, None

    # 直接路径命中（经容器边界校验）
    safe_path = safe_resolve_within(pocs_dir, poc_filename)
    if safe_path and os.path.exists(safe_path):
        return safe_path, os.path.relpath(safe_path, os.path.realpath(pocs_dir))

    # 按 basename 在 pocs_dir 树内查找（basename 已去除任何目录成分，天然防穿越）
    basename = os.path.basename(poc_filename)
    real_base = os.path.realpath(pocs_dir)
    for dirpath, _, filenames in os.walk(real_base):
        if basename in filenames:
            found = os.path.join(dirpath, basename)
            return found, os.path.relpath(found, real_base)

    # 内建（embedded）PoC：不落盘，返回逻辑路径
    builtin_code, normalized = get_poc_code(poc_filename)
    if builtin_code and normalized and is_executable_poc_name(normalized):
        safe_builtin = safe_resolve_within(pocs_dir, normalized)
        if safe_builtin:
            return safe_builtin, normalized

    return None, None


def resolve_poc_source(pocs_dir: str, poc_filename: str) -> tuple[str | None, str | None, str | None]:
    poc_path, normalized = resolve_poc_path(pocs_dir, poc_filename)
    if not poc_path or not normalized:
        return None, None, None

    if os.path.exists(poc_path):
        with open(poc_path, "r", encoding="utf-8") as handle:
            return poc_path, normalized, handle.read()

    builtin_code, builtin_name = get_poc_code(normalized)
    if builtin_code and builtin_name:
        return poc_path, builtin_name, builtin_code
    return poc_path, normalized, None


def list_available_poc_names(pocs_dir: str) -> list[str]:
    names: set[str] = set()
    if os.path.isdir(pocs_dir):
        for dirpath, dirnames, filenames in os.walk(pocs_dir):
            dirnames[:] = [
                d for d in dirnames
                if not d.startswith('.') and not d.startswith('_') and d != '.venv' and d != '__pycache__'
            ]
            for filename in filenames:
                if is_executable_poc_name(filename):
                    names.add(os.path.relpath(os.path.join(dirpath, filename), pocs_dir))
    names.update(name for name in list_builtin_pocs() if is_executable_poc_name(name))
    return sorted(names)

import os

from poc_registry import get_poc_code, list_builtin_pocs


SUPPORT_MODULES = {
    "iv_plugin_base.py",
    "poc_runtime_adapter.py",
    "advisory_audit_core.py",
    "active_validation_core.py",
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

    poc_path = os.path.join(pocs_dir, poc_filename)
    if os.path.exists(poc_path):
        return poc_path, os.path.relpath(poc_path, pocs_dir)

    basename = os.path.basename(poc_filename)
    for dirpath, _, filenames in os.walk(pocs_dir):
        if basename in filenames:
            poc_path = os.path.join(dirpath, basename)
            return poc_path, os.path.relpath(poc_path, pocs_dir)

    builtin_code, normalized = get_poc_code(poc_filename)
    if builtin_code and normalized:
        return os.path.join(pocs_dir, normalized), normalized

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

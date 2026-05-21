import base64
import os
from functools import lru_cache
from pathlib import Path


SERVER_DIR = Path(__file__).resolve().parent
POCS_DIR = SERVER_DIR / "pocs"

try:
    from generated_poc_registry import POC_CODE_B64_MAP as GENERATED_POC_CODE_B64_MAP
except Exception:
    GENERATED_POC_CODE_B64_MAP = {}


def _filesystem_poc_map() -> dict[str, str]:
    mapping: dict[str, str] = {}
    if not POCS_DIR.exists():
        return mapping
    for path in sorted(POCS_DIR.rglob("*.py")):
        if ".venv" in path.parts:
            continue
        rel_path = path.relative_to(POCS_DIR).as_posix()
        try:
            mapping[rel_path] = path.read_text(encoding="utf-8")
        except Exception:
            continue
    return mapping


@lru_cache(maxsize=1)
def get_poc_code_map() -> dict[str, str]:
    if GENERATED_POC_CODE_B64_MAP:
        return {
            path: base64.b64decode(encoded).decode("utf-8")
            for path, encoded in GENERATED_POC_CODE_B64_MAP.items()
        }
    return _filesystem_poc_map()


def normalize_poc_name(poc_name: str | None) -> str | None:
    if not poc_name:
        return None
    normalized = str(poc_name).replace("\\", "/").strip().lstrip("./")
    mapping = get_poc_code_map()
    if normalized in mapping:
        return normalized

    basename = os.path.basename(normalized)
    matches = [key for key in mapping if os.path.basename(key) == basename]
    if len(matches) == 1:
        return matches[0]
    return None


def has_builtin_poc(poc_name: str | None) -> bool:
    return normalize_poc_name(poc_name) is not None


def get_poc_code(poc_name: str | None) -> tuple[str | None, str | None]:
    normalized = normalize_poc_name(poc_name)
    if not normalized:
        return None, None
    return get_poc_code_map().get(normalized), normalized


def list_builtin_pocs() -> list[str]:
    return sorted(get_poc_code_map().keys())

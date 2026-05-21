import os
import platform
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent


def _load_env_file(path: Path) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue

        key, value = line.split('=', 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def load_environment() -> None:
    executable_dir = Path(sys.argv[0]).resolve().parent if sys.argv and sys.argv[0] else Path.cwd()
    candidates = [
        PROJECT_ROOT / '.env',
        PROJECT_ROOT / '.env.local',
        BASE_DIR / '.env',
        BASE_DIR / '.env.local',
        executable_dir / '.env',
        executable_dir / '.env.local',
    ]
    for candidate in candidates:
        _load_env_file(candidate)


load_environment()


@dataclass(frozen=True)
class AppConfig:
    secret_key: str
    database_uri: str
    autosec_api: str
    mcp_server: str
    flask_host: str
    flask_port: int
    flask_debug: bool


def _to_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}


def _normalize_database_uri(uri: str | None) -> str:
    default_sqlite_path = (get_runtime_data_dir() / 'autosec.db').resolve()
    if not uri:
        return f"sqlite:///{default_sqlite_path.as_posix()}"

    if not uri.startswith('sqlite:///'):
        return uri

    sqlite_path = uri[len('sqlite:///'):]
    path_obj = Path(sqlite_path)
    if not path_obj.is_absolute():
        path_obj = (PROJECT_ROOT / path_obj).resolve()

    path_obj.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{path_obj.as_posix()}"


def get_runtime_data_dir() -> Path:
    configured = os.environ.get('AUTOSEC_DATA_DIR')
    if configured:
        path = Path(configured).expanduser().resolve()
    elif not (
        getattr(sys, 'frozen', False)
        or hasattr(sys, '__compiled__')
        or os.environ.get('NUITKA_ONEFILE_PARENT')
        or os.environ.get('PYINSTALLER_SAFE_MODE')
    ):
        path = BASE_DIR
    else:
        system = platform.system().lower()
        if system == 'darwin':
            path = Path.home() / 'Library' / 'Application Support' / 'AutoSec Guard Edge'
        elif system == 'windows':
            path = Path(os.environ.get('LOCALAPPDATA') or Path.home() / 'AppData' / 'Local') / 'AutoSec Guard Edge'
        else:
            path = Path(os.environ.get('XDG_STATE_HOME') or Path.home() / '.local' / 'state') / 'autosec-guard-edge'
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_config() -> AppConfig:
    return AppConfig(
        secret_key=os.environ.get('AUTOSEC_SECRET_KEY') or secrets.token_urlsafe(32),
        database_uri=_normalize_database_uri(os.environ.get('AUTOSEC_DB_URI')),
        autosec_api=os.environ.get('AUTOSEC_API', 'http://localhost:5002'),
        mcp_server=os.environ.get('MCP_SERVER', 'http://localhost:5003'),
        flask_host=os.environ.get('AUTOSEC_HOST', '0.0.0.0'),
        flask_port=int(os.environ.get('AUTOSEC_PORT', '5002')),
        flask_debug=_to_bool(os.environ.get('AUTOSEC_DEBUG'), default=False),
    )


def get_runtime_warnings(config: AppConfig) -> List[str]:
    warnings: List[str] = []

    if 'AUTOSEC_SECRET_KEY' not in os.environ:
        warnings.append('AUTOSEC_SECRET_KEY not set; using an ephemeral development key.')

    if 'AUTOSEC_DB_URI' not in os.environ:
        warnings.append('AUTOSEC_DB_URI not set; using local SQLite database.')

    warnings.append('Edge-local product mode: PoC execution and hardware capability probing run on this workstation.')
    warnings.append('AI features require per-user AI configuration from the browser; the server does not use a shared model API key.')

    return warnings

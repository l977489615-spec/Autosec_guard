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
    ai_config_key: str
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


def is_packaged_runtime() -> bool:
    return bool(
        getattr(sys, 'frozen', False)
        or '__compiled__' in globals()
        or hasattr(sys, '__compiled__')
        or os.environ.get('NUITKA_ONEFILE_PARENT')
        or os.environ.get('PYINSTALLER_SAFE_MODE')
    )


def get_runtime_data_dir() -> Path:
    configured = os.environ.get('AUTOSEC_DATA_DIR')
    if configured:
        path = Path(configured).expanduser().resolve()
    elif not is_packaged_runtime():
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


_WEAK_SECRETS = {
    'change-me-before-delivery',
    'replace_with_a_long_random_secret',
    'secret',
    'changeme',
}


def _load_or_create_secret(env_name: str, filename: str) -> str:
    """Return a durable secret without shipping a shared default credential."""
    configured = str(os.environ.get(env_name) or '').strip()
    if configured:
        if configured.lower() in _WEAK_SECRETS or len(configured) < 32:
            raise RuntimeError(f'{env_name} must be at least 32 characters and must not use a documented placeholder.')
        return configured

    secret_path = get_runtime_data_dir() / filename
    if secret_path.exists():
        value = secret_path.read_text(encoding='utf-8').strip()
        if len(value) >= 32:
            return value

    value = secrets.token_urlsafe(48)
    secret_path.write_text(value + '\n', encoding='utf-8')
    try:
        secret_path.chmod(0o600)
    except OSError:
        pass
    return value


def get_config() -> AppConfig:
    # AUTOSEC_HOST 默认 127.0.0.1（仅本机访问，最小暴露面）。
    # 若需要跨网络访问（如在实验室局域网中共享），显式设置 AUTOSEC_HOST=0.0.0.0，
    # 并同时配置 TLS 反向代理和精确的 AUTOSEC_CORS_ORIGINS 白名单。
    flask_host = os.environ.get('AUTOSEC_HOST', '127.0.0.1')
    return AppConfig(
        secret_key=_load_or_create_secret('AUTOSEC_SECRET_KEY', '.session-secret'),
        ai_config_key=_load_or_create_secret('AUTOSEC_AI_CONFIG_KEY', '.ai-config-secret'),
        database_uri=_normalize_database_uri(os.environ.get('AUTOSEC_DB_URI')),
        autosec_api=os.environ.get('AUTOSEC_API', 'http://localhost:5002'),
        mcp_server=os.environ.get('MCP_SERVER', 'http://localhost:5003'),
        flask_host=flask_host,
        flask_port=int(os.environ.get('AUTOSEC_PORT', '5002')),
        flask_debug=_to_bool(os.environ.get('AUTOSEC_DEBUG'), default=False),
    )


def get_runtime_warnings(config: AppConfig) -> List[str]:
    warnings: List[str] = []

    if 'AUTOSEC_SECRET_KEY' not in os.environ:
        warnings.append('AUTOSEC_SECRET_KEY not set; using the durable per-installation session key.')

    if 'AUTOSEC_AI_CONFIG_KEY' not in os.environ:
        warnings.append('AUTOSEC_AI_CONFIG_KEY not set; using the durable per-installation AI encryption key.')

    if 'AUTOSEC_DB_URI' not in os.environ:
        warnings.append('AUTOSEC_DB_URI not set; using local SQLite database.')

    # 网络暴露面警告
    # Comparison only; actual non-loopback binds are checked by startup policy.
    if config.flask_host == '0.0.0.0':  # nosec B104
        cors_origins = os.environ.get('AUTOSEC_CORS_ORIGINS', '').strip()
        if not cors_origins:
            warnings.append(
                'CORS is disabled because AUTOSEC_CORS_ORIGINS is empty; use the same-origin UI or configure an explicit allowlist.'
            )

    warnings.append('Edge-local product mode: PoC execution and hardware capability probing run on this workstation.')
    warnings.append('AI features require per-user AI configuration from the browser; the server does not use a shared model API key.')

    return warnings

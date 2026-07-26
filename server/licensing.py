"""Offline, device-bound licensing for the AutoSec edge workstation."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import platform
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from config import get_runtime_data_dir
from generated_license_public_key import LICENSE_PUBLIC_KEY_B64


PRODUCT_ID = "autosec-guard-edge"
SCHEMA_VERSION = 1
ALL_FEATURES = frozenset({"scan", "poc_execution", "report_export"})
_CLOCK_ROLLBACK_TOLERANCE = dt.timedelta(minutes=5)


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _parse_utc(value: Any) -> dt.datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp is required")
    parsed = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def format_utc(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def licensing_enforced() -> bool:
    """Customer binaries always enforce licensing; source runs opt in."""
    packaged = bool(
        getattr(sys, "frozen", False)
        or "__compiled__" in globals()
        or hasattr(sys, "__compiled__")
        or os.environ.get("NUITKA_ONEFILE_PARENT")
        or os.environ.get("PYINSTALLER_SAFE_MODE")
    )
    if packaged:
        return True
    return os.environ.get("AUTOSEC_LICENSE_ENFORCEMENT", "off").strip().lower() in {"1", "true", "yes", "on"}


def _read_first(paths: list[Path]) -> str:
    for path in paths:
        try:
            value = path.read_text(encoding="utf-8").strip()
            if value:
                return value
        except OSError:
            continue
    return ""


def _platform_machine_anchor() -> str:
    system = platform.system().lower()
    if system == "windows":
        try:
            import winreg  # type: ignore

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                value, _ = winreg.QueryValueEx(key, "MachineGuid")
                if value:
                    return f"windows:{value}"
        except (OSError, ImportError):
            pass
    elif system == "darwin":
        try:
            result = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            for line in result.stdout.splitlines():
                if "IOPlatformUUID" in line and "=" in line:
                    return f"macos:{line.split('=', 1)[1].strip().strip(chr(34))}"
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        machine_id = _read_first([Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")])
        if machine_id:
            return f"linux:{machine_id}"
    # A hostname is not a strong identifier, but the per-installation ID below
    # still prevents a copied license from working in a fresh data directory.
    return f"fallback:{platform.node()}:{platform.machine()}"


def _load_or_create_private_text(path: Path, byte_count: int = 32) -> str:
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_hex(byte_count)
    path.write_text(value + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return value


def machine_code(data_dir: Path | None = None) -> str:
    data_dir = (data_dir or get_runtime_data_dir()).resolve()
    install_id = _load_or_create_private_text(data_dir / ".license-installation-id")
    material = f"{PRODUCT_ID}\n{_platform_machine_anchor()}\n{install_id}".encode("utf-8")
    digest = hashlib.sha256(material).hexdigest().upper()
    return "-".join(digest[index:index + 8] for index in range(0, len(digest), 8))


def normalize_machine_code(value: str) -> str:
    normalized = "".join(char for char in str(value or "") if char.isalnum()).upper()
    if len(normalized) != 64 or any(char not in "0123456789ABCDEF" for char in normalized):
        raise ValueError("machine_code must be a 64-character SHA-256 value")
    return "-".join(normalized[index:index + 8] for index in range(0, 64, 8))


class LicenseManager:
    def __init__(
        self,
        data_dir: Path | None = None,
        public_key_b64: str | None = None,
        enforced: bool | None = None,
        now_provider=None,
    ) -> None:
        self.data_dir = (data_dir or get_runtime_data_dir()).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.license_path = Path(os.environ.get("AUTOSEC_LICENSE_PATH") or self.data_dir / "license.autosec").resolve()
        self.public_key_b64 = (public_key_b64 if public_key_b64 is not None else LICENSE_PUBLIC_KEY_B64).strip()
        self.enforced = licensing_enforced() if enforced is None else enforced
        self._now = now_provider or _utc_now
        self._state_path = self.data_dir / ".license-clock-state"
        self._state_key_path = self.data_dir / ".license-state-key"

    @property
    def machine_code(self) -> str:
        return machine_code(self.data_dir)

    def _public_key(self) -> Ed25519PublicKey:
        try:
            raw = base64.b64decode(self.public_key_b64, validate=True)
            if len(raw) != 32:
                raise ValueError
            return Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError, TypeError) as exc:
            raise ValueError("license verification public key is not configured") from exc

    def _read_document(self) -> dict[str, Any]:
        with self.license_path.open("r", encoding="utf-8") as handle:
            document = json.load(handle)
        if not isinstance(document, dict):
            raise ValueError("license document must be an object")
        return document

    def _clock_state(self) -> dt.datetime | None:
        try:
            envelope = json.loads(self._state_path.read_text(encoding="utf-8"))
            value = str(envelope["last_seen_utc"])
            signature = str(envelope["hmac"])
            key = bytes.fromhex(self._state_key_path.read_text(encoding="utf-8").strip())
            expected = hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                return None
            return _parse_utc(value)
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None

    def _record_clock(self, now: dt.datetime) -> None:
        key_hex = _load_or_create_private_text(self._state_key_path)
        key = bytes.fromhex(key_hex)
        value = format_utc(now)
        envelope = {
            "last_seen_utc": value,
            "hmac": hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest(),
        }
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=".license-clock-", dir=str(self._state_path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(envelope, handle, ensure_ascii=False, sort_keys=True)
                handle.write("\n")
            os.replace(temp_name, self._state_path)
            try:
                self._state_path.chmod(0o600)
            except OSError:
                pass
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass

    def evaluate(self, document: dict[str, Any] | None = None, *, update_clock: bool = True) -> dict[str, Any]:
        base = {
            "enforced": self.enforced,
            "machine_code": self.machine_code,
            "product": PRODUCT_ID,
            "license_path": str(self.license_path),
        }
        if not self.enforced:
            return {**base, "valid": True, "state": "development", "features": sorted(ALL_FEATURES)}

        if not self.public_key_b64:
            return {**base, "valid": False, "state": "configuration_error", "message": "授权公钥未配置。"}

        try:
            document = document if document is not None else self._read_document()
        except FileNotFoundError:
            return {**base, "valid": False, "state": "missing", "message": "尚未安装离线许可证。"}
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return {**base, "valid": False, "state": "invalid_format", "message": f"许可证文件无法读取：{exc}"}

        try:
            payload = document["payload"]
            signature = base64.b64decode(document["signature"], validate=True)
            if not isinstance(payload, dict):
                raise ValueError("payload must be an object")
            self._public_key().verify(signature, canonical_payload(payload))
        except InvalidSignature:
            return {**base, "valid": False, "state": "invalid_signature", "message": "许可证签名无效或内容已被修改。"}
        except (KeyError, TypeError, ValueError) as exc:
            return {**base, "valid": False, "state": "invalid_format", "message": f"许可证格式无效：{exc}"}

        safe = {
            "license_id": str(payload.get("license_id") or ""),
            "customer": str(payload.get("customer") or ""),
            "edition": str(payload.get("edition") or ""),
            "expires_at": str(payload.get("expires_at") or ""),
            "features": sorted(set(payload.get("features") or [])),
            "key_id": str(payload.get("key_id") or ""),
        }
        try:
            if int(payload.get("schema")) != SCHEMA_VERSION:
                raise ValueError("unsupported schema")
            if payload.get("product") != PRODUCT_ID:
                raise ValueError("wrong product")
            if not safe["license_id"] or not safe["customer"]:
                raise ValueError("license_id and customer are required")
            licensed_machine = normalize_machine_code(str(payload.get("machine_code") or ""))
            if not hmac.compare_digest(licensed_machine, self.machine_code):
                return {**base, **safe, "valid": False, "state": "wrong_device", "message": "许可证与当前设备不匹配。"}
            not_before = _parse_utc(payload["not_before"])
            expires_at = _parse_utc(payload["expires_at"])
            if expires_at <= not_before:
                raise ValueError("expires_at must be after not_before")
            if not set(safe["features"]).issubset(ALL_FEATURES):
                raise ValueError("license contains unsupported features")
        except (KeyError, TypeError, ValueError) as exc:
            return {**base, **safe, "valid": False, "state": "invalid_claims", "message": f"许可证声明无效：{exc}"}

        now = self._now().astimezone(dt.timezone.utc)
        previous = self._clock_state()
        if previous and now + _CLOCK_ROLLBACK_TOLERANCE < previous:
            return {**base, **safe, "valid": False, "state": "clock_rollback", "message": "检测到系统时间回拨，请校准时间或联系供应商。"}
        if update_clock and (previous is None or now - previous >= dt.timedelta(minutes=10)):
            self._record_clock(now)
        if now < not_before:
            return {**base, **safe, "valid": False, "state": "not_yet_valid", "message": "许可证尚未生效。"}
        if now >= expires_at:
            return {**base, **safe, "valid": False, "state": "expired", "message": "许可证已到期，请导入续期许可证。"}

        remaining_seconds = max(0, int((expires_at - now).total_seconds()))
        return {
            **base,
            **safe,
            "valid": True,
            "state": "valid",
            "remaining_days": (remaining_seconds + 86399) // 86400,
            "message": "许可证有效。",
        }

    def feature_allowed(self, feature: str) -> tuple[bool, dict[str, Any]]:
        status = self.evaluate()
        return bool(status.get("valid") and feature in set(status.get("features") or [])), status

    def install(self, document: dict[str, Any]) -> dict[str, Any]:
        status = self.evaluate(document, update_clock=False)
        if not status.get("valid"):
            return status
        self.license_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=".license-install-", dir=str(self.license_path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(document, handle, ensure_ascii=False, sort_keys=True, indent=2)
                handle.write("\n")
            os.replace(temp_name, self.license_path)
            try:
                self.license_path.chmod(0o600)
            except OSError:
                pass
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
        return self.evaluate()

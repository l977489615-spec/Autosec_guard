#!/usr/bin/env python3
"""Vendor-side CLI for generating and issuing AutoSec offline licenses."""

from __future__ import annotations

import argparse
import base64
import calendar
import datetime as dt
import json
import os
import secrets
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from licensing import ALL_FEATURES, PRODUCT_ID, SCHEMA_VERSION, canonical_payload, format_utc, normalize_machine_code


def _password() -> bytes | None:
    value = os.environ.get("AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD", "")
    password_file = os.environ.get("AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD_FILE", "").strip()
    if value and password_file:
        raise SystemExit("set only one of AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD or AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD_FILE")
    if value:
        return value.encode("utf-8")
    if not password_file:
        return None
    path = Path(password_file).expanduser()
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if os.name != "nt" and mode & 0o077:
            raise SystemExit(f"password file must not be group/world accessible (expected chmod 600): {path}")
        return path.read_text(encoding="utf-8").strip().encode("utf-8")
    except OSError as exc:
        raise SystemExit(f"unable to read password file: {path}") from exc


def _write_private(path: Path, key: Ed25519PrivateKey) -> None:
    password = _password()
    if not password or len(password) < 16:
        raise SystemExit(
            "AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD must be set to at least 16 characters; "
            "unencrypted issuer keys are prohibited."
        )
    encryption = serialization.BestAvailableEncryption(password)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise SystemExit(f"refusing to overwrite existing private key: {path}")
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption))
    path.chmod(0o600)


def _write_public_module(path: Path, public_b64: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '"""Auto-generated public license verification key. Safe to distribute."""\n\n'
        f'LICENSE_PUBLIC_KEY_B64 = "{public_b64}"\n',
        encoding="utf-8",
    )


def generate_keypair(args: argparse.Namespace) -> int:
    key = Ed25519PrivateKey.generate()
    _write_private(args.private_key, key)
    public_raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    public_b64 = base64.b64encode(public_raw).decode("ascii")
    _write_public_module(args.public_module, public_b64)
    print(f"Private issuer key: {args.private_key}")
    print(f"Public verifier module: {args.public_module}")
    return 0


def protect_legacy_key(args: argparse.Namespace) -> int:
    """One-time migration of an unencrypted legacy issuer key."""
    password = _password()
    if not password or len(password) < 16:
        raise SystemExit("AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD must be at least 16 characters")
    try:
        key = serialization.load_pem_private_key(args.input.read_bytes(), password=None)
    except (OSError, TypeError, ValueError) as exc:
        raise SystemExit("input is not a readable unencrypted PEM private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("input private key is not an Ed25519 key")
    _write_private(args.output, key)
    print(f"Encrypted issuer key written: {args.output}")
    print("Verify license issuance, then securely delete the unencrypted input copy.")
    return 0


def _add_months(value: dt.datetime, months: int) -> dt.datetime:
    month_index = value.month - 1 + months
    year = value.year + month_index // 12
    month = month_index % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def _load_private(path: Path, password: bytes | None = None) -> Ed25519PrivateKey:
    password = password or _password()
    if not password:
        raise SystemExit("AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD is required to unlock the issuer key")
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=password)
    except (TypeError, ValueError) as exc:
        raise SystemExit("unable to unlock issuer key: wrong password or unencrypted legacy key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("private key is not an Ed25519 key")
    return key


def issue(args: argparse.Namespace, *, password: bytes | None = None) -> int:
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    if not args.customer.strip():
        raise SystemExit("customer must not be empty")
    if args.days is not None and args.days <= 0:
        raise SystemExit("days must be greater than zero")
    not_before = dt.datetime.fromisoformat(args.not_before.replace("Z", "+00:00")) if args.not_before else now
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=dt.timezone.utc)
    if args.expires_at:
        expires_at = dt.datetime.fromisoformat(args.expires_at.replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=dt.timezone.utc)
    elif args.days:
        expires_at = not_before + dt.timedelta(days=args.days)
    else:
        expires_at = _add_months(not_before, args.months)
    if expires_at <= not_before:
        raise SystemExit("license expiry must be after not-before")
    features = sorted({item.strip() for item in args.features.split(",") if item.strip()})
    unsupported = set(features) - ALL_FEATURES
    if unsupported:
        raise SystemExit(f"unsupported features: {', '.join(sorted(unsupported))}")
    payload = {
        "schema": SCHEMA_VERSION,
        "license_id": args.license_id or f"LIC-{now:%Y%m%d}-{secrets.token_hex(4).upper()}",
        "customer": args.customer.strip(),
        "product": PRODUCT_ID,
        "edition": args.edition,
        "issued_at": format_utc(now),
        "not_before": format_utc(not_before),
        "expires_at": format_utc(expires_at),
        "machine_code": normalize_machine_code(args.machine_code),
        "features": features,
        "key_id": args.key_id,
    }
    signature = _load_private(args.private_key, password=password).sign(canonical_payload(payload))
    document = {"payload": payload, "signature": base64.b64encode(signature).decode("ascii")}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"License written: {args.output}")
    print(f"License ID: {payload['license_id']}")
    print(f"Expires at: {payload['expires_at']}")
    return 0


def inspect_license(args: argparse.Namespace) -> int:
    document = json.loads(args.license.read_text(encoding="utf-8"))
    print(json.dumps(document.get("payload", {}), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AutoSec offline license issuer (vendor-side only).")
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("generate-keypair", help="Generate an Ed25519 issuer key and distributable public module.")
    keygen.add_argument("--private-key", type=Path, required=True)
    keygen.add_argument("--public-module", type=Path, default=Path(__file__).with_name("generated_license_public_key.py"))
    keygen.set_defaults(func=generate_keypair)

    protect = sub.add_parser("protect-key", help="Encrypt an existing unencrypted Ed25519 issuer key.")
    protect.add_argument("--input", type=Path, required=True)
    protect.add_argument("--output", type=Path, required=True)
    protect.set_defaults(func=protect_legacy_key)

    create = sub.add_parser("issue", help="Issue a device-bound offline license.")
    create.add_argument("--private-key", type=Path, required=True)
    create.add_argument("--customer", required=True)
    create.add_argument("--machine-code", required=True)
    duration = create.add_mutually_exclusive_group()
    duration.add_argument("--months", type=int, choices=range(1, 121), metavar="1..120", default=1)
    duration.add_argument("--days", type=int)
    duration.add_argument("--expires-at")
    create.add_argument("--not-before")
    create.add_argument("--license-id")
    create.add_argument("--edition", default="enterprise")
    create.add_argument("--features", default=",".join(sorted(ALL_FEATURES)))
    create.add_argument("--key-id", default="prod-2026-01")
    create.add_argument("--output", type=Path, required=True)
    create.set_defaults(func=issue)

    show = sub.add_parser("inspect", help="Display non-secret license claims.")
    show.add_argument("license", type=Path)
    show.set_defaults(func=inspect_license)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

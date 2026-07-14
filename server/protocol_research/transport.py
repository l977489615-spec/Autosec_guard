"""Bounded transport adapters for lab-only interaction."""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Any

from .models import bytes_to_hex, hex_to_bytes


@dataclass
class ExchangeResult:
    ok: bool
    request_hex: str
    response_hex: str
    elapsed_ms: float
    connection_state: str
    error: str = ""
    session_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "request_hex": self.request_hex,
            "response_hex": self.response_hex,
            "elapsed_ms": self.elapsed_ms,
            "connection_state": self.connection_state,
            "error": self.error,
            "session_id": self.session_id,
        }


class TcpStatefulSession:
    """One TCP connection reused across a message sequence."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout: float = 2.0,
        max_response_bytes: int = 4096,
        session_id: str = "",
    ) -> None:
        self.host = host
        self.port = int(port)
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.session_id = session_id or f"tcp-{host}:{port}-{int(time.time())}"
        self._sock: socket.socket | None = None
        self.closed = False

    def connect(self) -> None:
        if self._sock is not None:
            return
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._sock.settimeout(self.timeout)
        self.closed = False

    def send_recv(self, request_hex: str) -> ExchangeResult:
        payload = hex_to_bytes(request_hex)
        started = time.monotonic()
        try:
            self.connect()
            assert self._sock is not None
            self._sock.sendall(payload)
            try:
                data = self._sock.recv(self.max_response_bytes)
            except socket.timeout:
                data = b""
            elapsed = (time.monotonic() - started) * 1000
            return ExchangeResult(
                ok=True,
                request_hex=bytes_to_hex(payload),
                response_hex=bytes_to_hex(data),
                elapsed_ms=elapsed,
                connection_state="open",
                session_id=self.session_id,
            )
        except (OSError, socket.error) as exc:
            elapsed = (time.monotonic() - started) * 1000
            self.close()
            return ExchangeResult(
                ok=False,
                request_hex=bytes_to_hex(payload),
                response_hex="",
                elapsed_ms=elapsed,
                connection_state="error",
                error=type(exc).__name__,
                session_id=self.session_id,
            )

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self.closed = True

    def __enter__(self) -> "TcpStatefulSession":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class TcpTransportAdapter:
    """Stateful by default: one sequence keeps a single TCP session."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout: float = 2.0,
        max_response_bytes: int = 4096,
        rate_limit_s: float = 0.05,
        max_exchanges: int = 64,
        stateful: bool = True,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.rate_limit_s = rate_limit_s
        self.max_exchanges = max_exchanges
        self.stateful = bool(stateful)
        self._exchanges = 0
        self._active_session: TcpStatefulSession | None = None

    def exchange(self, request_hex: str) -> ExchangeResult:
        """Single-shot exchange (new connection) — for one-off probes only."""
        if self._exchanges >= self.max_exchanges:
            return ExchangeResult(
                ok=False,
                request_hex=request_hex,
                response_hex="",
                elapsed_ms=0.0,
                connection_state="budget_exhausted",
                error="max_exchanges reached",
            )
        self._exchanges += 1
        if self.rate_limit_s > 0:
            time.sleep(self.rate_limit_s)
        with TcpStatefulSession(
            self.host,
            self.port,
            timeout=self.timeout,
            max_response_bytes=self.max_response_bytes,
        ) as session:
            return session.send_recv(request_hex)

    def play_sequence(self, messages_hex: list[str]) -> list[ExchangeResult]:
        if not messages_hex:
            return []
        if not self.stateful:
            return [self.exchange(item) for item in messages_hex]

        results: list[ExchangeResult] = []
        session = TcpStatefulSession(
            self.host,
            self.port,
            timeout=self.timeout,
            max_response_bytes=self.max_response_bytes,
        )
        self._active_session = session
        try:
            for request_hex in messages_hex:
                if self._exchanges >= self.max_exchanges:
                    results.append(
                        ExchangeResult(
                            ok=False,
                            request_hex=request_hex,
                            response_hex="",
                            elapsed_ms=0.0,
                            connection_state="budget_exhausted",
                            error="max_exchanges reached",
                            session_id=session.session_id,
                        )
                    )
                    break
                self._exchanges += 1
                if self.rate_limit_s > 0:
                    time.sleep(self.rate_limit_s)
                results.append(session.send_recv(request_hex))
                if results[-1].connection_state == "error":
                    break
        finally:
            session.close()
            self._active_session = None
        return results


class DryRunTransportAdapter:
    """Stateful dry-run session for unit tests."""

    def __init__(self, scripted: dict[str, str] | None = None, *, stateful: bool = True) -> None:
        self.scripted = scripted or {}
        self.stateful = bool(stateful)
        self.calls: list[str] = []
        self._session_open = False
        self._session_id = f"dry-{int(time.time())}"

    def exchange(self, request_hex: str) -> ExchangeResult:
        self.calls.append(request_hex)
        response = self.scripted.get(request_hex, "")
        return ExchangeResult(
            ok=True,
            request_hex=request_hex,
            response_hex=response,
            elapsed_ms=0.1,
            connection_state="open",
            session_id=self._session_id,
        )

    def play_sequence(self, messages_hex: list[str]) -> list[ExchangeResult]:
        if not self.stateful:
            return [self.exchange(item) for item in messages_hex]
        self._session_open = True
        results = []
        for item in messages_hex:
            results.append(self.exchange(item))
        self._session_open = False
        return results

    @property
    def session_reused(self) -> bool:
        return len(self.calls) > 1 and self.stateful

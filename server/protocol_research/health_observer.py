"""Dynamic target health observation for fuzz oracles."""
from __future__ import annotations

import socket
import time
from typing import Any, Callable


class TcpPortHealthObserver:
    """Probe whether the authorized TCP port is still accepting connections."""

    def __init__(self, host: str, port: int, *, timeout: float = 1.0) -> None:
        self.host = str(host)
        self.port = int(port)
        self.timeout = float(timeout)
        self._baseline_alive: bool | None = None
        self._last_snapshot: dict[str, Any] = {}

    def probe_port(self) -> bool:
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout):
                return True
        except OSError:
            return False

    def snapshot(self, *, after_mutation: bool = False) -> dict[str, Any]:
        alive = self.probe_port()
        if self._baseline_alive is None:
            self._baseline_alive = alive
        port_gone = self._baseline_alive is True and not alive
        process_exited = port_gone and after_mutation
        self._last_snapshot = {
            "port_alive": alive,
            "port_gone": port_gone,
            "process_exited": process_exited,
            "environment_unstable": self._baseline_alive is False,
            "observed_at": time.time(),
        }
        return dict(self._last_snapshot)

    def as_health_fn(self, *, after_mutation: bool = False) -> Callable[[], dict[str, Any]]:
        return lambda: self.snapshot(after_mutation=after_mutation)


class ScriptedHealthObserver:
    """Test double — health evolves based on recent transport calls."""

    def __init__(self, *, baseline_alive: bool = True) -> None:
        self.baseline_alive = baseline_alive
        self.calls: list[str] = []
        self._crash_triggers: set[str] = set()

    def register_crash_on(self, request_hex: str) -> None:
        self._crash_triggers.add(request_hex)

    def observe_calls(self, calls: list[str]) -> None:
        self.calls = list(calls)

    def snapshot(self, *, after_mutation: bool = False) -> dict[str, Any]:
        crashed = after_mutation and any(call in self._crash_triggers for call in self.calls[-3:])
        return {
            "port_alive": not crashed,
            "port_gone": crashed,
            "process_exited": crashed,
            "environment_unstable": not self.baseline_alive,
            "observed_at": time.time(),
        }

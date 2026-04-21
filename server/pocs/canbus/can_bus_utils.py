from __future__ import annotations

from typing import Any, Mapping


DEFAULT_CAN_BITRATE = 500000
DEFAULT_CAN_INTERFACE = "PCAN_USBBUS1"


def _first_value(params: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = params.get(key)
        if value not in (None, ""):
            return value
    return default


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "fd"}
    return False


def _as_int(value: Any, default: int | None = None) -> int | None:
    if value in (None, ""):
        return default
    return int(value)


def _detect_backend(interface_name: str) -> str:
    name = (interface_name or "").strip().lower()
    if name.startswith("pcan") or "pcan_" in name or name.startswith("/dev/pcan"):
        return "pcan"
    if name.startswith("slcan"):
        return "slcan"
    return "socketcan"


def get_can_settings(params: Mapping[str, Any]) -> dict[str, Any]:
    interface_name = str(
        _first_value(params, "can_interface", "interface", default=DEFAULT_CAN_INTERFACE)
    ).strip() or DEFAULT_CAN_INTERFACE
    fd_enabled = _as_bool(_first_value(params, "can_fd", "fd_mode", "fd", default=False))
    settings = {
        "interface_name": interface_name,
        "backend": _detect_backend(interface_name),
        "bitrate": _as_int(params.get("can_bitrate"), DEFAULT_CAN_BITRATE),
        "fd_enabled": fd_enabled,
        "receive_own_messages": _as_bool(params.get("receive_own_messages")),
        "f_clock": _as_int(params.get("f_clock")),
        "f_clock_mhz": _as_int(params.get("f_clock_mhz")),
        "nom_brp": _as_int(params.get("nom_brp")),
        "nom_tseg1": _as_int(params.get("nom_tseg1")),
        "nom_tseg2": _as_int(params.get("nom_tseg2")),
        "nom_sjw": _as_int(params.get("nom_sjw")),
        "data_brp": _as_int(params.get("data_brp")),
        "data_tseg1": _as_int(params.get("data_tseg1")),
        "data_tseg2": _as_int(params.get("data_tseg2")),
        "data_sjw": _as_int(params.get("data_sjw")),
    }
    return settings


def format_can_settings(settings: Mapping[str, Any]) -> str:
    summary = (
        f"{settings['interface_name']} backend={settings['backend']} "
        f"bitrate={settings['bitrate']}"
    )
    if settings.get("fd_enabled"):
        summary += " fd=True"
    return summary


def open_can_bus(params: Mapping[str, Any]):
    import can

    settings = get_can_settings(params)
    backend = settings["backend"]
    interface_name = settings["interface_name"]

    if backend == "pcan":
        from can.interfaces.pcan.pcan import PcanBus

        kwargs = {
            "channel": interface_name,
            "bitrate": settings["bitrate"],
            "receive_own_messages": settings["receive_own_messages"],
        }
        if settings["fd_enabled"]:
            kwargs["fd"] = True
            fd_keys = [
                "f_clock",
                "f_clock_mhz",
                "nom_brp",
                "nom_tseg1",
                "nom_tseg2",
                "nom_sjw",
                "data_brp",
                "data_tseg1",
                "data_tseg2",
                "data_sjw",
            ]
            for key in fd_keys:
                if settings.get(key) is not None:
                    kwargs[key] = settings[key]
            if not any(key in kwargs for key in fd_keys):
                raise ValueError(
                    "PCAN FD mode requires explicit timing params "
                    "(for example f_clock_mhz/nom_* /data_*)."
                )
        return PcanBus(**kwargs)

    kwargs = {
        "channel": interface_name,
        "interface": backend,
        "receive_own_messages": settings["receive_own_messages"],
    }
    if settings["fd_enabled"]:
        kwargs["fd"] = True
    return can.Bus(**kwargs)

from typing import Any, Dict


def normalize_poc_params(raw_params: Dict[str, Any]) -> Dict[str, Any]:
    params = dict(raw_params or {})

    # Parameter mapping for plugin compatibility (ip -> target_ip, port -> target_port)
    if "ip" in params and "target_ip" not in params:
        params["target_ip"] = params["ip"]
    if "port" in params and "target_port" not in params:
        params["target_port"] = params["port"]

    # Bluetooth MAC mapping: bluetoothMac -> bd_addr / target_mac / bluetooth_mac
    bt_mac = params.get("bluetoothMac") or params.get("bluetooth_mac") or params.get("bd_addr") or ""
    if bt_mac:
        params["bd_addr"] = bt_mac
        params["target_mac"] = bt_mac
        params["bluetooth_mac"] = bt_mac

    return params


def resolve_target_label(params: Dict[str, Any]) -> str:
    return (
        params.get("target_ip")
        or params.get("target_mac")
        or params.get("can_interface")
        or "unknown"
    )

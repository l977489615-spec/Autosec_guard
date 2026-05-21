import os


def local_capability_flags(capabilities: dict) -> dict:
    socketcan_raw = str((capabilities.get("socketcan") or {}).get("interfaces") or "").lower()
    wifi_raw = str((capabilities.get("wifi") or {}).get("interfaces") or "").lower()
    bluetooth_raw = " ".join(
        [
            str((capabilities.get("bluetooth") or {}).get("bluetoothctl_list") or ""),
            str((capabilities.get("bluetooth") or {}).get("hciconfig") or ""),
        ]
    ).lower()
    usb_info = capabilities.get("usb") or {}
    sdr_info = capabilities.get("sdr") or {}
    host_tools = capabilities.get("host_tools") or {}
    pcan_chardev = capabilities.get("pcan_chardev") or {}
    python_can = capabilities.get("python_can") or {}
    python_can_interfaces = " ".join(
        [
            str(item)
            for item in (
                (python_can.get("interfaces") or []) +
                [cfg.get("interface") for cfg in (python_can.get("detected_configs") or []) if isinstance(cfg, dict)] +
                [cfg.get("channel") for cfg in (python_can.get("detected_configs") or []) if isinstance(cfg, dict)]
            )
            if item
        ]
    ).lower()

    return {
        "usb": bool(usb_info.get("mount_candidates") or usb_info.get("tty_usb") or usb_info.get("lsusb")),
        "can": (
            any(token in socketcan_raw for token in [" can", "\ncan", "pcan", "slcan", "vcan"]) or
            any(token in python_can_interfaces for token in ["pcan", "socketcan", "slcan", "can", "vcan"]) or
            pcan_chardev.get("present")
        ),
        "wifi": bool(wifi_raw.strip()),
        "bluetooth": bool(bluetooth_raw.strip()),
        "sdr": bool(str(sdr_info.get("hackrf_info") or "").strip() or str(sdr_info.get("rtl_test") or "").strip()),
        "lsusb": bool(host_tools.get("lsusb")),
        "iw": bool(host_tools.get("iw")),
        "ip": bool(host_tools.get("ip")),
        "bluetoothctl": bool(host_tools.get("bluetoothctl") or host_tools.get("hciconfig")),
        "hackrf": bool(host_tools.get("hackrf_info") or host_tools.get("rtl_test")),
        "pcan": bool(pcan_chardev.get("present") or usb_info.get("is_pcan_present") or "pcan" in python_can_interfaces),
    }


def infer_local_requirements(pocs_dir: str, profile: dict, poc_filename: str, params: dict | None = None) -> dict:
    params = params or {}
    protocol = str(profile.get("protocol") or "").lower()
    category = os.path.basename(os.path.dirname(os.path.join(pocs_dir, poc_filename))).lower()
    required_params = {str(item).lower() for item in (profile.get("required_params") or [])}
    joined_params = " ".join(sorted(required_params))
    filename = os.path.basename(poc_filename).lower()

    requires = {
        "usb": False,
        "can": False,
        "wifi": False,
        "bluetooth": False,
        "sdr": False,
    }

    if "usb" in protocol or "usb" in filename or "mount" in joined_params or "ttyusb" in joined_params:
        requires["usb"] = True
    if "can" in protocol or "uds" in protocol or "obd" in protocol or category == "canbus" or "can_interface" in required_params:
        requires["can"] = True
    if any(token in protocol for token in ["wifi", "wi-fi", "802.11"]) or category == "wireless":
        requires["wifi"] = True
    if any(token in protocol for token in ["bluetooth", "ble"]) or "bluetooth" in filename or "ble" in filename:
        requires["bluetooth"] = True
        requires["wifi"] = False
    if any(token in protocol for token in ["rf", "gps", "tpms", "v2x", "sdr"]) or any(token in filename for token in ["gps", "tpms", "v2x"]):
        requires["sdr"] = True

    if required_params & {"interface", "wifi_interface", "client_mac", "ssid", "bssid"}:
        requires["wifi"] = True
    if required_params & {"bluetooth_mac", "ble_address", "hci_interface"}:
        requires["bluetooth"] = True
        requires["wifi"] = False
    if required_params & {"rf_frequency", "frequency", "center_frequency", "tpms_frequency"}:
        requires["sdr"] = True
    if required_params & {"usb_mount_path", "usb_device", "serial_port", "tty_usb"}:
        requires["usb"] = True

    if params.get("can_interface"):
        requires["can"] = True
    if params.get("bluetooth_mac") or params.get("hci_interface"):
        requires["bluetooth"] = True
        requires["wifi"] = False
    if params.get("interface") or params.get("wifi_interface"):
        requires["wifi"] = True
    if params.get("rf_frequency") or params.get("frequency"):
        requires["sdr"] = True

    required = [name for name, enabled in requires.items() if enabled]
    return {
        "required_capabilities": required,
        "requires_edge": bool(required),
        "cloud_only": not bool(required),
    }


def classify_poc_execution_mode(pocs_dir: str, poc_path: str, profile: dict, poc_filename: str) -> dict:
    requirements = infer_local_requirements(pocs_dir, profile, poc_filename, {})
    text = ""
    try:
        with open(poc_path, "r", encoding="utf-8", errors="ignore") as handle:
            text = handle.read().lower()
    except Exception:
        text = ""

    manual_hints = (
        "manual",
        "人工",
        "观察目标",
        "观察车辆",
        "需确认",
        "awaiting manual",
        "requires manual",
        "插入目标车机",
        "u盘",
    )
    manual_confirmation = any(hint in text for hint in manual_hints)

    supported_planes = ["edge"] if requirements["requires_edge"] else ["cloud", "edge"]
    recommended_plane = "edge" if requirements["requires_edge"] else "cloud"

    return {
        "supported_execution_planes": supported_planes,
        "recommended_execution_plane": recommended_plane,
        "execution_requirements": requirements,
        "manual_confirmation_required": manual_confirmation,
    }

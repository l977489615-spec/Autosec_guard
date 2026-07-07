"""
PoC Name: USB ADB Debug Interface Detection
CVE: N/A
Component: Android Debug Bridge (ADB) over USB
Category: Network
Severity: High
CVSS: 8.2
Description: 枚举本机直连的 USB ADB 设备，确认车机是否暴露有线调试接口，并采集授权状态与关键系统属性。
Prerequisites: 扫描端已安装 adb 工具，且目标车机通过 USB 物理连接。
Usage: python3 01_USB_ADB_Debug.py [expected_usb_serial]
"""
import subprocess
import sys

from iv_plugin_base import IVIVulnerabilityPlugin


ADB_INFO_FIELDS = (
    "ro.product.manufacturer",
    "ro.product.model",
    "ro.build.version.release",
    "ro.debuggable",
    "ro.secure",
    "ro.adb.secure",
)

# ADB 连接状态 → 暴露等级（车联网场景：USB 调试口暴露本身即为攻击面）
EXPOSED_STATUSES = {"device", "unauthorized", "authorizing"}
HIGH_RISK_STATUSES = {"device"}


class USBADBDebugPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-001"
    meta_poc_name = "USB ADB Debug Interface Detection"
    meta_cve_id = "N/A"
    meta_severity = "High"
    meta_protocol = "usb"
    meta_target_os = ["android", "harmonyos"]
    meta_required_params = []
    meta_profiles = ["usb_adb"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        self.expected_usb_serial = str(
            self.params.get("expected_usb_serial")
            or self.params.get("usb_device_serial")
            or self.params.get("usbAdbSerial")
            or self.params.get("usb_adb_serial")
            or ""
        ).strip()
        # 默认：仅连接 1 台 USB 设备时自动视为目标（serial 用于多设备消歧，而非漏洞门槛）
        allow_param = self.params.get("allow_single_attached_match")
        self.allow_single_attached_match = (
            True if allow_param is None else allow_param in {True, "true", "True", "1", 1}
        )
        single_only = self.params.get("require_single_usb_device")
        self.require_single_usb_device = (
            True if single_only is None else single_only in {True, "true", "True", "1", 1}
        )
        self.timeout = int(self.params.get("timeout", 8))
        return True

    def _run_adb(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["adb", *args],
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )

    def _parse_devices(self, stdout: str) -> list[dict]:
        devices = []
        for raw_line in stdout.splitlines()[1:]:
            line = raw_line.strip()
            if not line or line.startswith("*"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            serial = parts[0]
            status = parts[1]
            if ":" in serial or serial.startswith("emulator-"):
                continue
            extra = {}
            for token in parts[2:]:
                if ":" in token:
                    key, value = token.split(":", 1)
                    extra[key] = value
            devices.append({"serial": serial, "status": status, "extra": extra})
        return devices

    def _collect_device_profile(self, serial: str) -> dict:
        profile = {}
        for field in ADB_INFO_FIELDS:
            try:
                proc = self._run_adb("-s", serial, "shell", "getprop", field)
                profile[field] = proc.stdout.strip() if proc.returncode == 0 else ""
            except Exception:
                profile[field] = ""
        try:
            state_proc = self._run_adb("-s", serial, "get-state")
            profile["adb_state"] = state_proc.stdout.strip() if state_proc.returncode == 0 else ""
        except Exception:
            profile["adb_state"] = ""
        try:
            id_proc = self._run_adb("-s", serial, "shell", "id")
            profile["shell_id"] = id_proc.stdout.strip() if id_proc.returncode == 0 else ""
        except Exception:
            profile["shell_id"] = ""
        return profile

    def _is_exposed(self, status: str) -> bool:
        return status in EXPOSED_STATUSES

    def _is_high_risk(self, status: str, profile: dict | None = None) -> bool:
        if status in HIGH_RISK_STATUSES:
            return True
        if not profile:
            return status in EXPOSED_STATUSES
        ro_debuggable = str(profile.get("ro.debuggable", "")).strip()
        ro_secure = str(profile.get("ro.secure", "")).strip()
        ro_adb_secure = str(profile.get("ro.adb.secure", "")).strip()
        shell_id = str(profile.get("shell_id", "")).strip()
        return (
            ro_debuggable == "1"
            or ro_secure == "0"
            or ro_adb_secure == "0"
            or "uid=" in shell_id
        )

    def _select_devices(self, wired_devices: list[dict]) -> tuple[list[dict], str]:
        """返回 (待深入评估的设备列表, 选择说明)。"""
        if self.expected_usb_serial:
            matched = [item for item in wired_devices if item["serial"] == self.expected_usb_serial]
            if matched:
                return matched, f"已按 expected_usb_serial={self.expected_usb_serial} 匹配目标设备。"
            return [], f"未匹配到 expected_usb_serial={self.expected_usb_serial}。"

        if len(wired_devices) == 1 and self.allow_single_attached_match:
            return wired_devices[:], "仅检测到 1 台 USB 设备，已自动作为评估目标。"

        return [], (
            f"检测到 {len(wired_devices)} 台 USB ADB 设备，实验要求仅连接 1 台；"
            "请拔掉多余设备，或在参数中指定 expected_usb_serial 以锁定目标。"
        )

    def _format_device_line(self, item: dict) -> str:
        product = item["extra"].get("product", "")
        model = item["extra"].get("model", "")
        return (
            f"  serial={item['serial']} status={item['status']} product={product} model={model}".strip()
        )

    def exploit(self):
        try:
            adb_result = self._run_adb("devices", "-l")
        except FileNotFoundError:
            self.results["evidence"] = "未安装 adb 命令行工具，无法执行有线 USB ADB 检测。"
            return self.results
        except Exception as exc:
            self.results["evidence"] = f"执行 adb devices 失败: {exc}"
            return self.results

        if adb_result.returncode != 0:
            self.results["evidence"] = (
                f"adb devices 执行失败: {adb_result.stderr.strip() or adb_result.stdout.strip() or 'unknown error'}"
            )
            return self.results

        wired_devices = self._parse_devices(adb_result.stdout)
        if not wired_devices:
            self.results["evidence"] = "当前系统未检出直连 USB ADB 设备。"
            return self.results

        if self.require_single_usb_device and len(wired_devices) > 1 and not self.expected_usb_serial:
            summary = [
                f"检测到 {len(wired_devices)} 台 USB ADB 设备，实验策略要求仅连接 1 台。",
                "请拔掉多余 USB Android 设备后重试。",
                *[self._format_device_line(item) for item in wired_devices],
            ]
            self.results["evidence"] = "\n".join(summary)
            return self.results

        summary_lines = [
            f"检测到 {len(wired_devices)} 个直连 USB ADB 设备:",
            *[self._format_device_line(item) for item in wired_devices],
        ]

        selected, selection_note = self._select_devices(wired_devices)
        summary_lines.append(selection_note)

        if not selected:
            # 指定了 serial 但未匹配：仍报告攻击面存在（其他设备可能暴露），但不判定为目标命中
            any_exposed = any(self._is_exposed(item["status"]) for item in wired_devices)
            self.results["vulnerable"] = any_exposed
            if any_exposed:
                summary_lines.append("目标 serial 未匹配，但检测到其他 USB ADB 暴露设备，仍标记为存在攻击面。")
            self.results["evidence"] = "\n".join(summary_lines)
            return self.results

        findings: list[str] = []
        vulnerable = False
        for item in selected:
            profile = self._collect_device_profile(item["serial"])
            status = item["status"]
            exposed = self._is_exposed(status)
            high_risk = self._is_high_risk(status, profile)

            if exposed:
                vulnerable = True

            risk_label = "高危" if high_risk else ("中危" if exposed else "信息")
            findings.extend([
                f"[{risk_label}] serial={item['serial']} status={status}",
                f"  manufacturer={profile.get('ro.product.manufacturer', '')}",
                f"  model={profile.get('ro.product.model', '')}",
                f"  android_version={profile.get('ro.build.version.release', '')}",
                f"  ro.debuggable={profile.get('ro.debuggable', '')}",
                f"  ro.secure={profile.get('ro.secure', '')}",
                f"  ro.adb.secure={profile.get('ro.adb.secure', '')}",
                f"  adb_state={profile.get('adb_state', '')}",
                f"  shell_id={profile.get('shell_id', '') or '(empty)'}",
            ])
            if status == "device":
                findings.append("  判定: USB ADB 已授权连接，调试接口可被利用。")
            elif status == "unauthorized":
                findings.append("  判定: USB ADB 调试口已开启，等待 RSA 授权（攻击面已暴露）。")
            elif status == "authorizing":
                findings.append("  判定: USB ADB 正在授权，调试口已暴露。")

        self.results["vulnerable"] = vulnerable
        self.results["evidence"] = "\n".join(summary_lines + [""] + findings)
        return self.results


if __name__ == "__main__":
    params = {}
    if len(sys.argv) >= 2:
        params["expected_usb_serial"] = sys.argv[1]
    plugin = USBADBDebugPlugin(params)
    plugin.run_verify()

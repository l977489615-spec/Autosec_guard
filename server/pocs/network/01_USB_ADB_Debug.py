"""
PoC Name: USB ADB Debug Interface Detection
CVE: N/A
Component: Android Debug Bridge (ADB) over USB
Category: Network
Severity: High
CVSS: 8.2
Description: 枚举本机直连的 USB ADB 设备，确认车机是否暴露有线调试接口，并采集授权状态与关键系统属性。
Prerequisites: 扫描端已安装 adb 工具，且目标车机通过 USB 物理连接。
Usage: python3 01_USB_ADB_Debug.py <expected_usb_serial>
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


class USBADBDebugPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-001"
    meta_poc_name = "USB ADB Debug Interface Detection"
    meta_cve_id = "N/A"
    meta_severity = "High"
    meta_protocol = "usb"
    meta_target_os = ["android", "harmonyos"]
    meta_required_params = []
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        self.expected_usb_serial = str(self.params.get("expected_usb_serial") or "").strip()
        self.allow_single_attached_match = self.params.get("allow_single_attached_match") in {True, "true", "True", "1", 1}
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

        matched = []
        if self.expected_usb_serial:
            matched = [item for item in wired_devices if item["serial"] == self.expected_usb_serial]
        elif len(wired_devices) == 1 and self.allow_single_attached_match:
            matched = wired_devices[:]

        summary_lines = [f"检测到 {len(wired_devices)} 个直连 USB ADB 设备:"]
        for item in wired_devices:
            product = item["extra"].get("product", "")
            model = item["extra"].get("model", "")
            summary_lines.append(
                f"  serial={item['serial']} status={item['status']} product={product} model={model}".strip()
            )

        if not matched:
            if self.expected_usb_serial:
                summary_lines.append(f"未匹配到 expected_usb_serial={self.expected_usb_serial}。")
            else:
                summary_lines.append("未提供 expected_usb_serial，保守处理为仅发现 USB ADB 攻击面，不直接判定目标命中。")
            self.results["evidence"] = "\n".join(summary_lines)
            return self.results

        target = matched[0]
        profile = self._collect_device_profile(target["serial"])
        ro_debuggable = str(profile.get("ro.debuggable", "")).strip()
        ro_secure = str(profile.get("ro.secure", "")).strip()
        ro_adb_secure = str(profile.get("ro.adb.secure", "")).strip()
        shell_id = str(profile.get("shell_id", "")).strip()

        self.results["vulnerable"] = (
            target["status"] == "device"
            and (
                ro_debuggable == "1"
                or ro_secure == "0"
                or ro_adb_secure == "0"
                or "uid=" in shell_id
            )
        )

        details = [
            f"匹配到目标 USB ADB 设备: serial={target['serial']} status={target['status']}",
            f"manufacturer={profile.get('ro.product.manufacturer', '')}",
            f"model={profile.get('ro.product.model', '')}",
            f"android_version={profile.get('ro.build.version.release', '')}",
            f"ro.debuggable={ro_debuggable}",
            f"ro.secure={ro_secure}",
            f"ro.adb.secure={ro_adb_secure}",
            f"adb_state={profile.get('adb_state', '')}",
            f"shell_id={shell_id or '(empty)'}",
        ]
        self.results["evidence"] = "\n".join(summary_lines + [""] + details)
        return self.results


if __name__ == "__main__":
    params = {}
    if len(sys.argv) >= 2:
        params["expected_usb_serial"] = sys.argv[1]
    plugin = USBADBDebugPlugin(params)
    plugin.run_verify()

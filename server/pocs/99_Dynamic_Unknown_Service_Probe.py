"""
PoC Name: Dynamic Unknown Service Probe
CVE: N/A
Component: Unknown Network Service
Category: Network
Severity: Medium
Description: 面向未知服务的协议感知型动态指纹与异常响应探测
Prerequisites: 目标 TCP 服务可达
"""
import socket
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin


class DynamicUnknownServiceProbePlugin(IVIVulnerabilityPlugin):
    meta_poc_name = "Dynamic Unknown Service Probe"
    meta_cve_id = "N/A"
    meta_severity = "Medium"
    meta_protocol = "tcp"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Probe"

    DEFAULT_PORTS = {
        "http": 80,
        "https": 443,
        "rtsp": 554,
        "telnet": 23,
        "adb": 5555,
        "qnx": 8000,
        "unknown": 23,
    }

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def _resolve_port(self) -> int:
        if self.target_port:
            return int(self.target_port)
        service_hint = str(self.params.get("service_hint") or "unknown").lower()
        return self.DEFAULT_PORTS.get(service_hint, self.DEFAULT_PORTS["unknown"])

    def _exchange(self, payload: bytes, recv_size: int = 2048) -> dict:
        started = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(float(self.params.get("timeout", self.timeout)))
                sock.connect((self.target_ip, self._resolve_port()))
                if payload:
                    sock.sendall(payload)
                response = sock.recv(recv_size)
            return {
                "ok": True,
                "elapsed_ms": round((time.time() - started) * 1000, 2),
                "response": response,
                "error": "",
            }
        except Exception as exc:
            return {
                "ok": False,
                "elapsed_ms": round((time.time() - started) * 1000, 2),
                "response": b"",
                "error": str(exc),
            }

    def _detect_protocol(self, banner: bytes) -> str:
        hint = str(self.params.get("service_hint") or "").strip().lower()
        if hint:
            return hint
        lowered = (banner or b"").lower()
        if lowered.startswith(b"http/") or b"server:" in lowered:
            return "http"
        if b"rtsp" in lowered:
            return "rtsp"
        if b"adb" in lowered or b"cnxn" in lowered:
            return "adb"
        if b"login:" in lowered or b"password:" in lowered or b"telnet" in lowered:
            return "telnet"
        return "unknown"

    def _probe_plan(self, protocol: str) -> list[tuple[str, bytes]]:
        host = self.target_ip
        if protocol == "http":
            return [
                ("baseline_http_head", f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()),
                ("malformed_http_header", f"GET / HTTP/1.1\r\nHost: {host}\r\nX-AutoSec-Probe: %%%%\r\nConnection: close\r\n\r\n".encode()),
            ]
        if protocol == "rtsp":
            return [
                ("baseline_rtsp_options", b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"),
                ("malformed_rtsp_method", b"AUTOSEC_PROBE * RTSP/1.0\r\nCSeq: 2\r\n\r\n"),
            ]
        if protocol == "telnet":
            return [
                ("baseline_telnet_newline", b"\r\n"),
                ("telnet_negotiation_probe", b"\xff\xfb\x01\xff\xfd\x03\r\n"),
            ]
        if protocol == "adb":
            return [
                ("baseline_adb_connect_probe", b"CNXN\x00\x00\x00\x01\x00\x10\x00\x00\x07\x00\x00\x00\x32\x02\x00\x00\xbc\xb1\xa7\xb1host::\x00"),
            ]
        return [
            ("baseline_empty_read", b""),
            ("short_ascii_probe", b"AutoSec-Probe\r\n"),
            ("bounded_binary_probe", b"\x00\x01\x02AUTOSEC\xff\r\n"),
        ]

    def _classify(self, baseline: dict, observations: list[dict]) -> tuple[str, list[str]]:
        confirmed = []
        suspicious = []
        baseline_ok = bool(baseline.get("ok"))

        for item in observations:
            response = item.get("response") or b""
            lowered = response.lower()
            label = item.get("label")
            if any(marker in lowered for marker in (b"traceback", b"stack trace", b"segmentation fault", b"assertion failed")):
                confirmed.append(f"{label}: explicit crash/debug marker in response")
            elif any(marker in lowered for marker in (b"exception", b"fatal", b"panic", b"internal error")):
                suspicious.append(f"{label}: abnormal error marker in response")
            elif baseline_ok and not item.get("ok"):
                suspicious.append(f"{label}: baseline succeeded but probe failed with {item.get('error')}")
            elif baseline_ok and abs(len(response) - int(baseline.get("response_len") or 0)) > 512:
                suspicious.append(f"{label}: response length diverged from baseline")

        if confirmed:
            return "confirmed", confirmed
        if len(suspicious) >= 2:
            return "suspicious", suspicious[:3]
        return "no_evidence", suspicious[:3]

    def exploit(self):
        target_port = self._resolve_port()
        self.results["description"] = "未知服务动态指纹与异常响应探测"
        self.results["cve_id"] = "N/A"

        try:
            banner_result = self._exchange(b"")
            banner = banner_result.get("response") or b""
            protocol = self._detect_protocol(banner)
            plan = self._probe_plan(protocol)

            observations = []
            baseline = {
                "ok": False,
                "response_len": 0,
                "error": "",
            }

            for index, (label, payload) in enumerate(plan):
                result = self._exchange(payload)
                response = result.get("response") or b""
                observation = {
                    "label": label,
                    "ok": result.get("ok"),
                    "elapsed_ms": result.get("elapsed_ms"),
                    "response_len": len(response),
                    "response_sample": response[:120].decode("utf-8", errors="replace"),
                    "error": result.get("error"),
                    "response": response,
                }
                observations.append(observation)
                if index == 0:
                    baseline = {
                        "ok": observation["ok"],
                        "response_len": observation["response_len"],
                        "error": observation["error"],
                    }
                time.sleep(float(self.params.get("probe_interval_seconds", 0.2)))

            status, evidence_items = self._classify(baseline, observations[1:])
            self.results["vulnerable"] = status == "confirmed"
            self.results["evidence"] = (
                f"target={self.target_ip}:{target_port}; protocol={protocol}; "
                f"status={status}; evidence={'; '.join(evidence_items) if evidence_items else 'no repeatable abnormal evidence'}"
            )
            self.results["dynamic_probe"] = {
                "status": status,
                "protocol": protocol,
                "target": f"{self.target_ip}:{target_port}",
                "baseline": baseline,
                "observations": [
                    {key: value for key, value in item.items() if key != "response"}
                    for item in observations
                ],
            }
        except Exception as exc:
            self.logger.error(f"动态未知服务探测执行异常: {exc}")
            self.results["vulnerable"] = False
            self.results["evidence"] = f"Exception: {exc}"
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 99_Dynamic_Unknown_Service_Probe.py <target_ip> [target_port]")
        sys.exit(1)
    params = {"target_ip": sys.argv[1]}
    if len(sys.argv) >= 3:
        params["target_port"] = int(sys.argv[2])
    plugin = DynamicUnknownServiceProbePlugin(params)
    plugin.run_verify()

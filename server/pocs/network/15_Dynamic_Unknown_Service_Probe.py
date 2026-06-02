"""
PoC Name: Dynamic Unknown Service Probe
CVE: N/A
Component: Unknown Network Service
Category: Network
Severity: Medium
Description: 对未知 TCP 服务进行低风险协议指纹探测，采集 banner、响应长度和异常响应证据。
Prerequisites: 目标 IP 可达；可选 target_port 或 candidate_ports。
Usage: python3 15_Dynamic_Unknown_Service_Probe.py <target_ip> [target_port]
"""
import socket
import sys
import time

from iv_plugin_base import IVIVulnerabilityPlugin


DEFAULT_PORTS = [22, 23, 80, 443, 554, 1883, 5555, 7000, 8000, 8080, 8443, 13400, 30490]
PROBES = [
    ("empty", b""),
    ("http_head", b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"),
    ("http_options", b"OPTIONS * HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"),
    ("adb_cnxn_hint", b"CNXN\x00\x00\x00\x01\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb1\xa7\xb1"),
    ("mqtt_connect_hint", b"\x10\x0e\x00\x04MQTT\x04\x02\x00<\x00\x00"),
    ("generic_newline", b"\r\n"),
]


class DynamicUnknownServiceProbePlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-015"
    meta_poc_name = "Dynamic Unknown Service Probe"
    meta_cve_id = "N/A"
    meta_severity = "Medium"
    meta_protocol = "tcp"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    meta_profiles = ["unknown_service", "network"]
    is_disruptive = False
    meta_destructive_level = "Probe"

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标 IP 地址。")
        raw_ports = self.params.get("target_port") or self.params.get("candidate_ports") or ""
        self.ports = self._parse_ports(raw_ports)
        self.timeout = float(self.params.get("timeout", 2.0) or 2.0)
        return True

    def _parse_ports(self, raw_value):
        if isinstance(raw_value, int):
            return [raw_value]
        if isinstance(raw_value, str) and raw_value.strip():
            ports = []
            for part in raw_value.replace(";", ",").split(","):
                try:
                    port = int(part.strip())
                except ValueError:
                    continue
                if 1 <= port <= 65535 and port not in ports:
                    ports.append(port)
            if ports:
                return ports
        if self.target_port:
            return [int(self.target_port)]
        return DEFAULT_PORTS

    def _probe_once(self, port: int, probe_name: str, payload: bytes) -> dict:
        started = time.time()
        item = {
            "port": port,
            "probe": probe_name,
            "open": False,
            "response_hex": "",
            "response_text": "",
            "elapsed_ms": 0,
            "error": "",
        }
        try:
            with socket.create_connection((self.target_ip, port), timeout=self.timeout) as sock:
                item["open"] = True
                sock.settimeout(self.timeout)
                if payload:
                    sock.sendall(payload)
                try:
                    data = sock.recv(512)
                except socket.timeout:
                    data = b""
                item["response_hex"] = data[:128].hex()
                item["response_text"] = data[:128].decode("utf-8", errors="replace")
        except (OSError, socket.timeout) as exc:
            item["error"] = str(exc)
        finally:
            item["elapsed_ms"] = round((time.time() - started) * 1000, 2)
        return item

    def exploit(self):
        findings = []
        open_ports = set()
        for port in self.ports:
            for probe_name, payload in PROBES:
                result = self._probe_once(port, probe_name, payload)
                if result["open"]:
                    open_ports.add(port)
                    findings.append(result)
                if result["response_hex"]:
                    break

        if not findings:
            self.results["vulnerable"] = False
            self.results["evidence"] = f"未在候选端口 {self.ports} 上发现可连接的未知 TCP 服务。"
            return self.results

        evidence_lines = [
            f"发现 {len(open_ports)} 个可连接端口: {sorted(open_ports)}",
            "该 PoC 只做低风险协议指纹探测，不直接判定漏洞成功。",
        ]
        for item in findings[:20]:
            response = item["response_text"] or item["response_hex"] or item["error"] or "no response"
            evidence_lines.append(
                f"port={item['port']} probe={item['probe']} elapsed_ms={item['elapsed_ms']} response={response[:160]}"
            )

        self.results["vulnerable"] = True
        self.results["evidence"] = "\n".join(evidence_lines)
        self.results["details"] = {"open_ports": sorted(open_ports), "probe_results": findings[:50]}
        return self.results


if __name__ == "__main__":
    params = {}
    if len(sys.argv) >= 2:
        params["target_ip"] = sys.argv[1]
    if len(sys.argv) >= 3:
        params["target_port"] = sys.argv[2]
    plugin = DynamicUnknownServiceProbePlugin(params)
    plugin.run_verify()

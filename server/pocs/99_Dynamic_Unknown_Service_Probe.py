"""
PoC Name: Dynamic Unknown Service Probe
CVE: N/A
Component: Unknown Network Service
Category: Network
Severity: Medium
Description: 面向未知车载网络服务的协议识别、低扰动差分探测与证据确认
Prerequisites: 目标 TCP/UDP 服务可达
"""
import socket
import ssl
import struct
import sys
import time
from dataclasses import dataclass

from iv_plugin_base import IVIVulnerabilityPlugin


@dataclass(frozen=True)
class ProbeSpec:
    label: str
    payload: bytes
    transport: str = "tcp"
    recv_size: int = 4096
    risk: str = "safe"
    purpose: str = "fingerprint"
    sequence_payloads: tuple[bytes, ...] = ()


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
        "ssh": 22,
        "adb": 5555,
        "mqtt": 1883,
        "someip": 30490,
        "doip": 13400,
        "qnx": 8000,
    }
    CANDIDATE_PORTS = [
        80,
        443,
        554,
        1883,
        8883,
        13400,
        30490,
        5555,
        22,
        23,
        7000,
        8000,
        8080,
        8443,
        3804,
        5000,
        5001,
    ]

    CRASH_MARKERS = (
        b"traceback",
        b"stack trace",
        b"segmentation fault",
        b"assertion failed",
        b"core dumped",
        b"panic:",
        b"fatal signal",
    )
    ERROR_MARKERS = (
        b"exception",
        b"fatal",
        b"panic",
        b"internal error",
        b"out of bounds",
        b"invalid memory",
        b"asan:",
        b"ubsan:",
    )
    AUTH_MARKERS = (
        b"login:",
        b"password:",
        b"unauthorized",
        b"forbidden",
        b"authentication",
        b"authorization",
    )

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        self._resolve_port()
        return True

    def _int_param(self, name: str, default: int, minimum: int, maximum: int) -> int:
        try:
            value = int(self.params.get(name, default))
        except Exception:
            value = default
        return max(minimum, min(maximum, value))

    def _float_param(self, name: str, default: float, minimum: float, maximum: float) -> float:
        try:
            value = float(self.params.get(name, default))
        except Exception:
            value = default
        return max(minimum, min(maximum, value))

    def _resolve_port(self) -> int:
        cached = getattr(self, "_resolved_target_port", None)
        if cached:
            return int(cached)

        if self.target_port:
            self._resolved_target_port = int(self.target_port)
            return self._resolved_target_port

        service_hint = str(self.params.get("service_hint") or "unknown").lower()
        if service_hint in self.DEFAULT_PORTS:
            self._resolved_target_port = self.DEFAULT_PORTS[service_hint]
            return self._resolved_target_port

        discovered = self._discover_candidate_port()
        if discovered:
            self._resolved_target_port = discovered
            return self._resolved_target_port

        raise RuntimeError("未指定 target_port，且未在候选车载服务端口中发现可连接服务。")

    def _candidate_ports(self) -> list[int]:
        raw_ports = self.params.get("candidate_ports")
        ports: list[int] = []
        if isinstance(raw_ports, str):
            for item in raw_ports.replace(";", ",").split(","):
                item = item.strip()
                if item.isdigit():
                    ports.append(int(item))
        elif isinstance(raw_ports, (list, tuple, set)):
            for item in raw_ports:
                try:
                    ports.append(int(item))
                except Exception:
                    continue

        ports.extend(self.CANDIDATE_PORTS)
        unique_ports = []
        seen = set()
        for port in ports:
            if 1 <= int(port) <= 65535 and int(port) not in seen:
                unique_ports.append(int(port))
                seen.add(int(port))
        return unique_ports[: self._int_param("max_candidate_ports", 24, 1, 128)]

    def _tcp_port_open(self, port: int) -> bool:
        try:
            with socket.create_connection(
                (self.target_ip, int(port)),
                timeout=self._float_param("port_probe_timeout", 0.35, 0.1, 3.0),
            ):
                return True
        except Exception:
            return False

    def _discover_candidate_port(self) -> int | None:
        for port in self._candidate_ports():
            if self._tcp_port_open(port):
                return port
        return None

    def _timeout(self) -> float:
        default_timeout = min(float(self.timeout), 1.5)
        return self._float_param("probe_timeout", default_timeout, 0.3, 10.0)

    def _sleep_between_probes(self):
        time.sleep(self._float_param("probe_interval_seconds", 0.18, 0.0, 2.0))

    def _tcp_exchange(self, payload: bytes, recv_size: int = 4096, use_tls: bool = False) -> dict:
        started = time.time()
        try:
            with socket.create_connection((self.target_ip, self._resolve_port()), timeout=self._timeout()) as sock:
                sock.settimeout(self._timeout())
                active_sock = sock
                tls_info = {}
                if use_tls:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    active_sock = context.wrap_socket(sock, server_hostname=self.target_ip)
                    tls_info = {
                        "tls_cipher": str(active_sock.cipher()),
                        "tls_version": active_sock.version(),
                    }
                if payload:
                    active_sock.sendall(payload)
                try:
                    response = active_sock.recv(recv_size)
                except socket.timeout:
                    response = b""
                return {
                    "ok": True,
                    "elapsed_ms": round((time.time() - started) * 1000, 2),
                    "response": response,
                    "error": "",
                    **tls_info,
                }
        except Exception as exc:
            return {
                "ok": False,
                "elapsed_ms": round((time.time() - started) * 1000, 2),
                "response": b"",
                "error": f"{exc.__class__.__name__}: {exc}",
            }

    def _tcp_sequence_exchange(self, payloads: tuple[bytes, ...], recv_size: int = 4096, use_tls: bool = False) -> dict:
        started = time.time()
        chunks = []
        step_lengths = []
        try:
            with socket.create_connection((self.target_ip, self._resolve_port()), timeout=self._timeout()) as sock:
                sock.settimeout(self._timeout())
                active_sock = sock
                tls_info = {}
                if use_tls:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    active_sock = context.wrap_socket(sock, server_hostname=self.target_ip)
                    tls_info = {
                        "tls_cipher": str(active_sock.cipher()),
                        "tls_version": active_sock.version(),
                    }
                for payload in payloads:
                    if payload:
                        active_sock.sendall(payload)
                    try:
                        response = active_sock.recv(recv_size)
                    except socket.timeout:
                        response = b""
                    chunks.append(response)
                    step_lengths.append(len(response))
                    self._sleep_between_probes()
            return {
                "ok": True,
                "elapsed_ms": round((time.time() - started) * 1000, 2),
                "response": b"\n---AUTOSEC_STEP---\n".join(chunks),
                "error": "",
                "state_steps": step_lengths,
                **tls_info,
            }
        except Exception as exc:
            return {
                "ok": False,
                "elapsed_ms": round((time.time() - started) * 1000, 2),
                "response": b"\n---AUTOSEC_STEP---\n".join(chunks),
                "error": f"{exc.__class__.__name__}: {exc}",
                "state_steps": step_lengths,
            }

    def _udp_exchange(self, payload: bytes, recv_size: int = 4096) -> dict:
        started = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self._timeout())
                sock.sendto(payload, (self.target_ip, self._resolve_port()))
                try:
                    response, _ = sock.recvfrom(recv_size)
                except socket.timeout:
                    response = b""
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
                "error": f"{exc.__class__.__name__}: {exc}",
            }

    def _run_probe(self, spec: ProbeSpec) -> dict:
        if spec.sequence_payloads and spec.transport in {"tcp", "tls"}:
            result = self._tcp_sequence_exchange(spec.sequence_payloads, spec.recv_size, use_tls=spec.transport == "tls")
        elif spec.transport == "udp":
            result = self._udp_exchange(spec.payload, spec.recv_size)
        elif spec.transport == "tls":
            result = self._tcp_exchange(spec.payload, spec.recv_size, use_tls=True)
        else:
            result = self._tcp_exchange(spec.payload, spec.recv_size)

        response = result.get("response") or b""
        return {
            "label": spec.label,
            "transport": spec.transport,
            "purpose": spec.purpose,
            "risk": spec.risk,
            "ok": bool(result.get("ok")),
            "elapsed_ms": result.get("elapsed_ms"),
            "response_len": len(response),
            "response_sample": response[:180].decode("utf-8", errors="replace"),
            "response_hex": response[:48].hex(),
            "error": result.get("error", ""),
            "tls_version": result.get("tls_version", ""),
            "tls_cipher": result.get("tls_cipher", ""),
            "state_steps": result.get("state_steps", []),
            "_response": response,
        }

    def _mqtt_connect_packet(self, client_id: str = "autosec_probe") -> bytes:
        variable_header = b"\x00\x04MQTT\x04\x02\x00\x0f"
        client = client_id.encode("ascii", errors="ignore")[:48]
        payload = struct.pack("!H", len(client)) + client
        remaining = len(variable_header) + len(payload)
        return b"\x10" + bytes([remaining]) + variable_header + payload

    def _doip_vehicle_identification(self) -> bytes:
        # ISO 13400 generic vehicle identification request: version, inverse, payload type, length.
        return b"\x02\xfd\x00\x01\x00\x00\x00\x00"

    def _someip_sd_find_service(self) -> bytes:
        # SOME/IP-SD header with empty entries/options. Safe discovery-style packet.
        return (
            b"\xff\xff\x81\x00"
            b"\x00\x00\x00\x10"
            b"\x00\x00\x00\x01"
            b"\x01\x01\x02\x00"
            b"\x00\x00\x00\x00"
        )

    def _fingerprint_probes(self) -> list[ProbeSpec]:
        host = self.target_ip
        return [
            ProbeSpec("passive_banner_read", b"", "tcp", purpose="baseline"),
            ProbeSpec("http_head_fingerprint", f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()),
            ProbeSpec("rtsp_options_fingerprint", b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: AutoSec-Probe\r\n\r\n"),
            ProbeSpec("mqtt_connect_fingerprint", self._mqtt_connect_packet()),
            ProbeSpec("adb_connect_fingerprint", b"CNXN\x00\x00\x00\x01\x00\x10\x00\x00\x07\x00\x00\x00\x32\x02\x00\x00\xbc\xb1\xa7\xb1host::\x00"),
            ProbeSpec("doip_vehicle_identification", self._doip_vehicle_identification()),
            ProbeSpec("someip_sd_find_service", self._someip_sd_find_service(), "udp"),
            ProbeSpec("tls_handshake_fingerprint", b"", "tls"),
        ]

    def _score_protocols(self, observations: list[dict]) -> dict:
        scores = {
            "http": 0,
            "rtsp": 0,
            "telnet": 0,
            "ssh": 0,
            "adb": 0,
            "mqtt": 0,
            "doip": 0,
            "someip": 0,
            "tls": 0,
            "unknown": 1,
        }
        service_hint = str(self.params.get("service_hint") or "").strip().lower()
        if service_hint in scores:
            scores[service_hint] += 8

        for item in observations:
            label = item.get("label", "")
            response = item.get("_response") or b""
            lowered = response.lower()
            text = lowered + str(item.get("error", "")).lower().encode("utf-8", errors="ignore")

            if response.startswith(b"HTTP/") or b"\r\nserver:" in lowered or b"\r\nwww-authenticate:" in lowered:
                scores["http"] += 5
            if b"rtsp/" in lowered or b"cseq:" in lowered:
                scores["rtsp"] += 5
            if b"ssh-" in lowered:
                scores["ssh"] += 6
            if b"login:" in lowered or b"password:" in lowered or b"telnet" in lowered:
                scores["telnet"] += 4
            if b"adb" in lowered or b"cnxn" in lowered or b"device::" in lowered:
                scores["adb"] += 5
            if label.startswith("mqtt") and item.get("ok") and response[:1] in {b"\x20", b"\x40", b"\xe0"}:
                scores["mqtt"] += 5
            if len(response) >= 8 and response[:2] in {b"\x02\xfd", b"\x03\xfc"}:
                scores["doip"] += 6
            if len(response) >= 16 and label.startswith("someip"):
                scores["someip"] += 3
            if item.get("tls_version"):
                scores["tls"] += 5
            if b"wrong version number" in text or b"unknown protocol" in text:
                scores["tls"] -= 2

        port = self._resolve_port()
        port_hints = {
            22: "ssh",
            23: "telnet",
            80: "http",
            443: "tls",
            554: "rtsp",
            1883: "mqtt",
            30490: "someip",
            13400: "doip",
            5555: "adb",
        }
        if port in port_hints:
            scores[port_hints[port]] += 2
        return scores

    def _determine_protocol(self, observations: list[dict]) -> tuple[str, dict]:
        scores = self._score_protocols(observations)
        protocol = max(scores, key=scores.get)
        if scores[protocol] <= 2:
            protocol = "unknown"
        return protocol, scores

    def _protocol_probe_plan(self, protocol: str) -> list[ProbeSpec]:
        host = self.target_ip
        bounded_binary = b"\x00\x01\x02AUTOSEC_BOUNDARY\xff\r\n"
        if protocol in {"http", "tls"}:
            transport = "tls" if protocol == "tls" else "tcp"
            return [
                ProbeSpec("http_baseline_options", f"OPTIONS / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode(), transport, purpose="baseline"),
                ProbeSpec("http_malformed_header_boundary", f"GET / HTTP/1.1\r\nHost: {host}\r\nX-AutoSec-Probe: {'A' * 96}\r\nX-AutoSec-Probe: %%%%\r\nConnection: close\r\n\r\n".encode(), transport, purpose="field_boundary"),
                ProbeSpec("http_invalid_method_boundary", f"AUTOSEC_{'B' * 32} / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode(), transport, purpose="method_boundary"),
                ProbeSpec("http_admin_exposure_check", f"HEAD /admin HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode(), transport, purpose="unauth_exposure"),
                ProbeSpec("http_metrics_exposure_check", f"GET /metrics HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode(), transport, purpose="info_exposure"),
            ]
        if protocol == "rtsp":
            return [
                ProbeSpec("rtsp_baseline_options", b"OPTIONS * RTSP/1.0\r\nCSeq: 10\r\n\r\n", purpose="baseline"),
                ProbeSpec("rtsp_invalid_method_boundary", b"AUTOSEC_PROBE * RTSP/1.0\r\nCSeq: 11\r\n\r\n", purpose="method_boundary"),
                ProbeSpec("rtsp_header_boundary", b"DESCRIBE rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: 12\r\nUser-Agent: " + b"A" * 120 + b"\r\n\r\n", purpose="field_boundary"),
            ]
        if protocol == "mqtt":
            return [
                ProbeSpec("mqtt_baseline_connect", self._mqtt_connect_packet("autosec_baseline"), purpose="baseline"),
                ProbeSpec("mqtt_oversized_clientid_boundary", self._mqtt_connect_packet("A" * 48), purpose="field_boundary"),
                ProbeSpec("mqtt_malformed_remaining_length", b"\x10\xff\xff\xff\x7f" + b"\x00\x04MQTT", purpose="parser_boundary"),
            ]
        if protocol == "doip":
            return [
                ProbeSpec("doip_baseline_vehicle_identification", self._doip_vehicle_identification(), purpose="baseline"),
                ProbeSpec("doip_entity_status_request", b"\x02\xfd\x40\x01\x00\x00\x00\x00", purpose="diagnostic_exposure"),
                ProbeSpec("doip_invalid_payload_length", b"\x02\xfd\x00\x01\x00\x00\x01\x00", purpose="parser_boundary"),
            ]
        if protocol == "someip":
            return [
                ProbeSpec("someip_sd_baseline", self._someip_sd_find_service(), "udp", purpose="baseline"),
                ProbeSpec("someip_malformed_length_boundary", b"\xff\xff\x81\x00\xff\xff\xff\xf0\x00\x00\x00\x01\x01\x01\x02\x00", "udp", purpose="parser_boundary"),
            ]
        if protocol == "adb":
            return [
                ProbeSpec("adb_baseline_connect", b"CNXN\x00\x00\x00\x01\x00\x10\x00\x00\x07\x00\x00\x00\x32\x02\x00\x00\xbc\xb1\xa7\xb1host::\x00", purpose="baseline"),
                ProbeSpec("adb_host_features_query", b"OPEN\x01\x00\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00\x97\x04\x00\x00\x30\xfb\xb1\xb0host:features\x00", purpose="unauth_exposure"),
            ]
        if protocol == "telnet":
            return [
                ProbeSpec("telnet_baseline_newline", b"\r\n", purpose="baseline"),
                ProbeSpec("telnet_negotiation_boundary", b"\xff\xfb\x01\xff\xfd\x03\r\n", purpose="negotiation_boundary"),
                ProbeSpec("telnet_auth_prompt_check", b"autosec_probe\r\n", purpose="auth_surface"),
            ]
        if protocol == "ssh":
            return [
                ProbeSpec("ssh_baseline_banner", b"SSH-2.0-AutoSec_Probe\r\n", purpose="baseline"),
                ProbeSpec("ssh_version_boundary", b"SSH-2.0-" + b"A" * 128 + b"\r\n", purpose="field_boundary"),
            ]
        return [
            ProbeSpec("unknown_baseline_empty_read", b"", purpose="baseline"),
            ProbeSpec("unknown_ascii_boundary", b"AutoSec-Probe\r\n", purpose="generic_probe"),
            ProbeSpec("unknown_binary_boundary", bounded_binary, purpose="generic_probe"),
            ProbeSpec("unknown_length_prefixed_boundary", struct.pack("!I", 16) + b"AUTOSEC_BOUNDARY", purpose="parser_boundary"),
            ProbeSpec("unknown_json_rpc_probe", b'{"jsonrpc":"2.0","method":"autosec_probe","params":[],"id":1}\r\n', purpose="semantic_probe"),
            ProbeSpec(
                "unknown_state_sequence_probe",
                b"",
                purpose="state_sequence",
                sequence_payloads=(b"", b"HELP\r\n", b"VERSION\r\n", b"STATUS\r\n"),
            ),
        ]

    def _response_markers(self, response: bytes) -> tuple[list[str], list[str]]:
        lowered = (response or b"").lower()
        crash = [marker.decode("ascii", errors="ignore") for marker in self.CRASH_MARKERS if marker in lowered]
        errors = [marker.decode("ascii", errors="ignore") for marker in self.ERROR_MARKERS if marker in lowered]
        return crash, errors

    def _service_alive(self) -> bool:
        result = self._tcp_exchange(b"", 256)
        return bool(result.get("ok"))

    def _classify_observations(self, baseline: dict, observations: list[dict], protocol: str) -> tuple[str, list[str], int]:
        confirmed: list[str] = []
        suspicious: list[str] = []
        score = 0
        baseline_ok = bool(baseline.get("ok"))
        baseline_len = int(baseline.get("response_len") or 0)
        baseline_elapsed = float(baseline.get("elapsed_ms") or 0)

        for item in observations:
            label = item.get("label", "")
            response = item.get("_response") or b""
            lowered = response.lower()
            crash_markers, error_markers = self._response_markers(response)

            if crash_markers:
                confirmed.append(f"{label}: explicit crash/debug marker {','.join(crash_markers[:2])}")
                score += 40
                continue
            if error_markers:
                suspicious.append(f"{label}: abnormal parser/runtime marker {','.join(error_markers[:2])}")
                score += 16

            if baseline_ok and not item.get("ok"):
                suspicious.append(f"{label}: baseline succeeded but probe failed ({item.get('error')})")
                score += 10

            response_len = int(item.get("response_len") or 0)
            if baseline_ok and baseline_len and abs(response_len - baseline_len) > max(512, baseline_len * 4):
                suspicious.append(f"{label}: response length diverged from baseline ({baseline_len}->{response_len})")
                score += 8

            elapsed = float(item.get("elapsed_ms") or 0)
            if baseline_elapsed > 0 and elapsed > max(baseline_elapsed * 5, baseline_elapsed + 1500):
                suspicious.append(f"{label}: response latency diverged from baseline ({baseline_elapsed}ms->{elapsed}ms)")
                score += 8

            if item.get("purpose") in {"unauth_exposure", "diagnostic_exposure"}:
                if protocol == "http" and lowered.startswith(b"http/") and any(code in lowered[:32] for code in (b" 200 ", b" 204 ", b" 206 ")):
                    if not any(marker in lowered for marker in self.AUTH_MARKERS):
                        suspicious.append(f"{label}: unauthenticated management-like endpoint returned success")
                        score += 14
                if protocol == "adb" and (b"device::" in lowered or b"features" in lowered):
                    suspicious.append(f"{label}: ADB service disclosed unauthenticated device features")
                    score += 18
                if protocol == "doip" and len(response) >= 8 and response[:2] in {b"\x02\xfd", b"\x03\xfc"}:
                    suspicious.append(f"{label}: DoIP diagnostic endpoint responded to unauthenticated request")
                    score += 14

        alive_after = self._service_alive()
        if baseline_ok and not alive_after:
            suspicious.append("post_probe_liveness: service stopped responding after bounded probes")
            score += 18

        if confirmed:
            return "confirmed", confirmed[:5], max(score, 80)
        if score >= 34 and len(suspicious) >= 2:
            return "suspicious", suspicious[:6], score
        if score >= 18:
            return "weak_signal", suspicious[:4], score
        return "no_evidence", suspicious[:3], score

    def _confirm_suspicion(self, protocol: str, suspicious_labels: list[str]) -> dict:
        rounds = self._int_param("confirm_rounds", 2, 1, 4)
        replay_hits = 0
        replay_observations = []
        if not suspicious_labels:
            return {"confirmed": False, "rounds": 0, "hits": 0, "observations": []}

        selected = []
        labels = {item.split(":", 1)[0] for item in suspicious_labels}
        for spec in self._protocol_probe_plan(protocol):
            if spec.label in labels:
                selected.append(spec)
        selected = selected[:3]

        for _ in range(rounds):
            for spec in selected:
                self._sleep_between_probes()
                observation = self._run_probe(spec)
                crash_markers, error_markers = self._response_markers(observation.get("_response") or b"")
                hit = bool(crash_markers or error_markers or (not observation.get("ok")))
                if hit:
                    replay_hits += 1
                replay_observations.append({key: value for key, value in observation.items() if key != "_response"})

        required_hits = max(1, min(2, len(selected)))
        return {
            "confirmed": replay_hits >= required_hits,
            "rounds": rounds,
            "hits": replay_hits,
            "required_hits": required_hits,
            "observations": replay_observations,
        }

    def exploit(self):
        target_port = self._resolve_port()
        self.results["description"] = "未知车载网络服务协议识别、低扰动差分探测与证据确认"
        self.results["cve_id"] = "N/A"

        try:
            max_probes = self._int_param("max_probe_count", 12, 4, 32)
            observations = []

            for spec in self._fingerprint_probes()[:max_probes]:
                observation = self._run_probe(spec)
                observations.append(observation)
                self._sleep_between_probes()

            protocol, scores = self._determine_protocol(observations)
            plan = self._protocol_probe_plan(protocol)
            remaining_budget = max(0, max_probes - len(observations))
            if remaining_budget:
                for spec in plan[:remaining_budget]:
                    observation = self._run_probe(spec)
                    observations.append(observation)
                    self._sleep_between_probes()

            protocol_observations = [item for item in observations if item.get("label") in {spec.label for spec in plan}]
            baseline = next((item for item in protocol_observations if item.get("purpose") == "baseline"), None)
            if not baseline:
                baseline = observations[0] if observations else {"ok": False, "response_len": 0, "elapsed_ms": 0}

            status, evidence_items, risk_score = self._classify_observations(
                baseline,
                [item for item in protocol_observations if item is not baseline],
                protocol,
            )
            confirmation = {}
            if status in {"suspicious", "confirmed"}:
                confirmation = self._confirm_suspicion(protocol, evidence_items)
                if status == "suspicious" and confirmation.get("confirmed"):
                    status = "confirmed_repeatable"
                    risk_score = max(risk_score, 70)

            self.results["vulnerable"] = status in {"confirmed", "confirmed_repeatable"}
            evidence_text = (
                "; ".join(evidence_items)
                if status in {"weak_signal", "suspicious", "confirmed", "confirmed_repeatable"} and evidence_items
                else "no repeatable abnormal evidence"
            )
            self.results["evidence"] = (
                f"target={self.target_ip}:{target_port}; protocol={protocol}; "
                f"status={status}; risk_score={risk_score}; "
                f"evidence={evidence_text}"
            )
            self.results["dynamic_probe"] = {
                "status": status,
                "risk_score": risk_score,
                "protocol": protocol,
                "protocol_scores": scores,
                "target": f"{self.target_ip}:{target_port}",
                "baseline": {key: value for key, value in baseline.items() if key != "_response"},
                "observations": [
                    {key: value for key, value in item.items() if key != "_response"}
                    for item in observations
                ],
                "confirmation": confirmation,
                "safe_probe_policy": {
                    "max_probe_count": max_probes,
                    "confirm_rounds": self._int_param("confirm_rounds", 2, 1, 4),
                    "destructive_payloads": False,
                    "state_changing_actions": False,
                },
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

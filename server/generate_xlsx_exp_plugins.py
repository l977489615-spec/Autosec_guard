#!/usr/bin/env python3
"""Generate active-validation EXP plugins from the connected-vehicle XLSX list."""
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import openpyxl


SERVER_DIR = Path(__file__).resolve().parent
POCS_DIR = SERVER_DIR / "pocs"
DEFAULT_XLSX = SERVER_DIR.parent.parent / "connected_vehicle_ivi_vuln_100_nonduplicates.xlsx"


HEADERS = (
    "序号",
    "漏洞编号",
    "年份",
    "领域",
    "厂商/产品",
    "影响组件/接口",
    "漏洞类型",
    "漏洞简述",
    "严重性/评分",
    "PoC状态",
    "主来源URL",
    "补充来源URL",
    "研究价值备注",
)


@dataclass(frozen=True)
class PluginSpec:
    row_id: int
    display_id: str
    cve: str
    year: int
    category: str
    output_path: Path
    class_name: str
    file_stem: str
    poc_name: str
    severity: str
    protocol: str
    required_params: list[str]
    profiles: list[str]
    target_os: list[str]
    vendor_product: str
    component: str
    vuln_type: str
    summary: str
    poc_status: str
    source_url: str
    references: list[str]
    research_value: str
    attack_surface: str
    probe_kind: str
    sample_suffix: str
    sample_param: str
    command_params: tuple[str, ...]
    phenomenon: str
    operator_action: str
    signature_tokens: list[str]


def load_records(xlsx_path: str | Path = DEFAULT_XLSX) -> list[dict[str, Any]]:
    workbook = openpyxl.load_workbook(Path(xlsx_path), read_only=True, data_only=True)
    worksheet = workbook["新增漏洞清单100"]
    rows = list(worksheet.iter_rows(values_only=True))
    headers = [str(item or "").strip() for item in rows[0]]
    records: list[dict[str, Any]] = []
    for row in rows[1:]:
        if not row or not row[0]:
            continue
        item = dict(zip(headers, row))
        records.append({key: item.get(key) for key in HEADERS})
    return records


def build_plugin_specs(records: list[dict[str, Any]]) -> list[PluginSpec]:
    specs: list[PluginSpec] = []
    seen_classes: set[str] = set()
    next_numbers = existing_next_numbers()
    for record in records:
        row_id = int(record["序号"])
        cve = str(record["漏洞编号"]).strip()
        year = int(record.get("年份") or 0)
        domain = clean_text(record.get("领域"))
        vendor_product = clean_text(record.get("厂商/产品"))
        component = clean_text(record.get("影响组件/接口"))
        vuln_type = clean_text(record.get("漏洞类型"))
        summary = clean_text(record.get("漏洞简述"))
        poc_status = clean_text(record.get("PoC状态"))
        source_url = clean_text(record.get("主来源URL"))
        supplement = clean_text(record.get("补充来源URL"))
        research_value = clean_text(record.get("研究价值备注"))
        category = classify_category(domain, component, vuln_type, vendor_product)
        probe_kind = classify_probe_kind(domain, component, vuln_type, summary)
        protocol, required_params, profiles, target_os = classify_runtime(category, probe_kind, domain, component)
        severity = normalize_severity(clean_text(record.get("严重性/评分")))
        display_id = f"XLSX2-{row_id:03d}"
        name_bits = [vendor_product, component, vuln_type]
        file_label = sanitize_identifier("_".join(name_bits), max_parts=7)
        file_number = next_numbers[category]
        next_numbers[category] += 1
        file_stem = f"{file_number:02d}_{file_label}_Audit"
        class_base = sanitize_identifier(f"Xlsx2_{row_id:03d}_{cve}_{category}_{probe_kind}", max_parts=10)
        class_name = f"{class_base}Plugin"
        while class_name in seen_classes:
            class_name = f"{class_base}{len(seen_classes)}Plugin"
        seen_classes.add(class_name)
        sample_suffix, sample_param, command_params = sample_contract(probe_kind)
        attack_surface = infer_attack_surface(domain, component, vuln_type)
        specs.append(
            PluginSpec(
                row_id=row_id,
                display_id=display_id,
                cve=cve,
                year=year,
                category=category,
                output_path=POCS_DIR / category / f"{file_stem}.py",
                class_name=class_name,
                file_stem=file_stem,
                poc_name=f"{cve} {vuln_type} Active Validation",
                severity=severity,
                protocol=protocol,
                required_params=required_params,
                profiles=profiles,
                target_os=target_os,
                vendor_product=vendor_product,
                component=component,
                vuln_type=vuln_type,
                summary=summary,
                poc_status=poc_status,
                source_url=source_url,
                references=[url for url in (source_url, supplement) if url],
                research_value=research_value,
                attack_surface=attack_surface,
                probe_kind=probe_kind,
                sample_suffix=sample_suffix,
                sample_param=sample_param,
                command_params=command_params,
                phenomenon=build_phenomenon(probe_kind, cve, component, vuln_type),
                operator_action=build_operator_action(probe_kind),
                signature_tokens=signature_tokens(cve, vendor_product, component, vuln_type, summary),
            )
        )
    return specs


def render_plugin(spec: PluginSpec) -> str:
    return f'''#!/usr/bin/env python3
"""Active validation EXP harness generated from connected-vehicle IVI XLSX data."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin
from local_exp_stimulus import build_local_sample_probe, write_temp_sample, write_temp_text


VULN = {python_repr({
        "id": spec.row_id,
        "cve": spec.cve,
        "year": spec.year,
        "domain": spec.category,
        "vendor_product": spec.vendor_product,
        "component": spec.component,
        "type": spec.vuln_type,
        "summary": spec.summary,
        "source_description": spec.summary,
        "poc_status": f"{spec.poc_status}; AutoSec生成受控EXP harness，破坏性触发需 allow_disruptive=true",
        "research_value": spec.research_value,
        "source_url": spec.source_url,
        "references": spec.references,
        "requires_manual_review": True,
        "affected": [{"vendor": spec.vendor_product.split()[0] if spec.vendor_product else "Unknown", "product": spec.vendor_product, "versions": [{"version": "*", "status": "affected"}]}],
        "signature_tokens": spec.signature_tokens,
    })}


stimulus_profile = {python_repr(build_stimulus_profile(spec))}


def _write_generated_sample() -> str:
{render_sample_writer(spec)}


def _xlsx2_probe(plugin, vuln):
    return build_local_sample_probe(
        plugin,
        sample_param="{spec.sample_param}",
        command_params={python_repr(spec.command_params)},
        generated_sample=_write_generated_sample,
        phenomenon="{escape_for_py(spec.phenomenon)}",
        operator_action="{escape_for_py(spec.operator_action)}",
    )


class {spec.class_name}(IVIVulnerabilityPlugin):
    meta_display_id = "{spec.display_id}"
    meta_poc_name = "{escape_for_py(spec.poc_name)}"
    meta_cve_id = "{spec.cve}"
    meta_severity = "{spec.severity}"
    meta_protocol = "{spec.protocol}"
    meta_target_os = {python_repr(spec.target_os)}
    meta_required_params = {python_repr(spec.required_params)}
    meta_profiles = {python_repr(spec.profiles)}
    meta_source_url = "{escape_for_py(spec.source_url)}"
    meta_attack_surface = "{escape_for_py(spec.attack_surface)}"
    is_disruptive = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_xlsx2_probe)
'''


def build_stimulus_profile(spec: PluginSpec) -> dict[str, Any]:
    return {
        "trigger_family": spec.probe_kind,
        "cve": spec.cve,
        "vendor_product": spec.vendor_product,
        "component": spec.component,
        "vulnerability_type": spec.vuln_type,
        "source_basis": spec.summary,
        "safety": "non-weaponized lab stimulus; destructive observation requires allow_disruptive=true and operator review",
    }


def render_sample_writer(spec: PluginSpec) -> str:
    safe_cve = safe_lower(spec.cve)
    if spec.probe_kind == "firmware_update":
        content = "\n".join([
            "format=autosec-update-manifest-v1",
            f"cve={spec.cve}",
            f"product={spec.vendor_product}",
            f"component={spec.component}",
            "package_name=lab_boundary_update.pkg",
            "signature=INVALID_LAB_SIGNATURE_EXPECT_REJECT",
            "install_phase=preinstall",
            "path_probe=../../../../tmp/autosec_path_boundary",
            "hook_probe=__AUTOSEC_BLOCKED_COMMAND_BOUNDARY__",
            "expected=reject unsigned package or expose parser/update-service crash in isolated bench",
        ])
        return _indented_text_writer(safe_cve, spec.sample_suffix, content)
    if spec.probe_kind == "command_injection":
        content = "\n".join([
            "format=autosec-command-boundary-manifest-v1",
            f"cve={spec.cve}",
            f"product={spec.vendor_product}",
            f"component={spec.component}",
            "field=update_argument",
            "value=normal_token;__AUTOSEC_BLOCKED_SEPARATOR__&&quoted_boundary",
            "env_probe=${AUTOSEC_LITERAL_ONLY}",
            "expected=no shell execution; observe parser rejection, crash, or command-boundary violation only in lab",
        ])
        return _indented_text_writer(safe_cve, spec.sample_suffix, content)
    if spec.probe_kind == "bluetooth_protocol":
        label = f"{spec.cve}|{spec.component}|{spec.vuln_type}".encode("utf-8")
        if "sdp" in spec.component.lower():
            payload = b"BTSDP" + b"\x02\x00\x01\x00\xff\xff" + len(label).to_bytes(2, "big") + label
        elif "hfp" in spec.component.lower() or "headset" in spec.component.lower():
            payload = b"AT+BRSF=" + b"9" * 96 + b"\r\n+BIND:" + label[:80] + b"\r\n"
        else:
            payload = b"OBEX" + b"\x83" + (len(label) + 12).to_bytes(2, "big") + b"\x42" + label
        return _indented_binary_writer(safe_cve, spec.sample_suffix, payload, "bluetooth_frame")
    if spec.probe_kind == "wifi_protocol":
        ssid = re.sub(r"[^A-Za-z0-9_-]+", "_", spec.component)[:64].encode("ascii", errors="ignore")
        payload = b"\x00\x00\x08\x00" + b"WIFI-PROBE" + len(ssid).to_bytes(1, "big") + ssid + b"\xdd" + bytes([min(250, len(ssid) + 8)]) + b"AUTOSec"
        return _indented_binary_writer(safe_cve, spec.sample_suffix, payload, "wifi_management_frame")
    if spec.probe_kind == "media_parser":
        component_l = spec.component.lower()
        label = f"{spec.cve}:{spec.component}:{spec.vuln_type}".encode("utf-8")
        if "carplay" in component_l or "tlv" in component_l:
            payload = b"TLV0" + (0x7FFFFFF0).to_bytes(4, "big") + label
        elif "webp" in component_l:
            payload = b"RIFF" + (len(label) + 32).to_bytes(4, "little") + b"WEBPVP8L" + b"\xff\xff\x7f\x00" + label
        elif "ffmpeg" in component_l or "media" in component_l:
            payload = b"RIFF" + (len(label) + 64).to_bytes(4, "little") + b"AVI LIST" + b"\xff" * 8 + label
        else:
            payload = b"PARSE" + len(label).to_bytes(4, "big") + label + b"\x00BOUNDARY\x00"
        return _indented_binary_writer(safe_cve, spec.sample_suffix, payload, "parser_container")
    if spec.probe_kind == "local_privilege":
        if "qualcomm" in spec.vendor_product.lower():
            content = "\n".join([
                "{",
                f'  "cve": "{spec.cve}",',
                f'  "product": "{_json_escape(spec.vendor_product)}",',
                f'  "component": "{_json_escape(spec.component)}",',
                f'  "vulnerability_type": "{_json_escape(spec.vuln_type)}",',
                '  "trigger_family": "bsp_driver_boundary",',
                '  "driver_probe": {',
                f'    "subsystem": "{_json_escape(spec.component.lower())}",',
                '    "device_node": "/dev/autosec_lab_driver",',
                '    "ioctl_selector": "AUTOSEC_SIZE_BOUNDARY_CHECK",',
                '    "buffer_length": 65535,',
                '    "dma_or_shared_memory": "metadata_only_no_kernel_write",',
                '    "expected": "patched driver rejects request; vulnerable lab build may report crash, warning, or sanitizer finding"',
                "  }",
                "}",
            ])
            return _indented_text_writer(safe_cve, spec.sample_suffix, content)
        content = "\n".join([
            "{",
            f'  "cve": "{spec.cve}",',
            f'  "product": "{_json_escape(spec.vendor_product)}",',
            f'  "component": "{_json_escape(spec.component)}",',
            f'  "vulnerability_type": "{_json_escape(spec.vuln_type)}",',
            '  "trigger_family": "local_privilege_boundary",',
            '  "binder_or_intent_probe": {',
            '    "caller_uid": 20000,',
            '    "target_uid": 1000,',
            '    "permission": "android.car.permission.CONTROL_CAR_APP_LAB_ONLY",',
            '    "parcel_size": 65535,',
            '    "expected": "permission denial, safe rejection, service crash, or explicit privilege-boundary violation"',
            "  }",
            "}",
        ])
        return _indented_text_writer(safe_cve, spec.sample_suffix, content)
    content = "\n".join([
        "{",
        f'  "cve": "{spec.cve}",',
        f'  "product": "{_json_escape(spec.vendor_product)}",',
        f'  "component": "{_json_escape(spec.component)}",',
        f'  "vulnerability_type": "{_json_escape(spec.vuln_type)}",',
        '  "trigger_family": "application_input_boundary",',
        '  "fields": {',
        '    "length_field": 4294967295,',
        '    "state_transition": "unauthorized_lab_probe",',
        '    "expected": "safe rejection, crash, or unauthorized state transition in isolated bench"',
        "  }",
        "}",
    ])
    return _indented_text_writer(safe_cve, spec.sample_suffix, content)


def _indented_text_writer(prefix: str, suffix: str, content: str) -> str:
    return (
        "    content = " + repr(content) + "\n"
        f"    return write_temp_text(\"autosec_{prefix}_\", \"{suffix}\", content)\n"
    )


def _indented_binary_writer(prefix: str, suffix: str, payload: bytes, label: str) -> str:
    return (
        "    payload = " + repr(payload) + "\n"
        f"    # trigger_family={label}\n"
        f"    return write_temp_sample(\"autosec_{prefix}_\", \"{suffix}\", payload)\n"
    )


def _json_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def write_plugins(specs: list[PluginSpec]) -> list[Path]:
    remove_existing_xlsx2_plugins()
    written: list[Path] = []
    for spec in specs:
        spec.output_path.parent.mkdir(parents=True, exist_ok=True)
        spec.output_path.write_text(render_plugin(spec), encoding="utf-8")
        written.append(spec.output_path)
    return written


def existing_next_numbers() -> dict[str, int]:
    numbers = {}
    for category in ("application", "network", "wireless", "advanced"):
        category_dir = POCS_DIR / category
        max_seen = 0
        for path in category_dir.glob("*.py"):
            match = re.match(r"^(\d+)_", path.name)
            if not match:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                text = ""
            if "meta_display_id = \"XLSX2-" in text or "meta_display_id = 'XLSX2-" in text:
                continue
            max_seen = max(max_seen, int(match.group(1)))
        numbers[category] = max_seen + 1
    return numbers


def remove_existing_xlsx2_plugins() -> None:
    for category in ("application", "network", "wireless", "advanced"):
        for path in (POCS_DIR / category).glob("*.py"):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if "meta_display_id = \"XLSX2-" in text or "meta_display_id = 'XLSX2-" in text:
                path.unlink()


def classify_category(domain: str, component: str, vuln_type: str, vendor_product: str) -> str:
    text = f"{domain} {component} {vuln_type} {vendor_product}".lower()
    if any(token in text for token in ("蓝牙", "bluetooth", "ble", "wi-fi", "wifi", "wpa", "wireless")):
        return "wireless"
    if any(token in text for token in ("qualcomm", "bsp", "芯片", "closed-source", "closed_source")):
        return "advanced"
    if "android" in text or "aaos" in text:
        return "application"
    if any(token in text for token in ("kernel", "内核")):
        return "advanced"
    if any(token in text for token in ("固件", "firmware", "ota", "update", "更新", "usb更新", "证书", "签名")):
        return "network"
    return "application"


def classify_probe_kind(domain: str, component: str, vuln_type: str, summary: str) -> str:
    text = f"{domain} {component} {vuln_type} {summary}".lower()
    if any(token in text for token in ("蓝牙", "bluetooth", "ble", "pbap", "l2cap", "avdtp", "sdp")):
        return "bluetooth_protocol"
    if any(token in text for token in ("wi-fi", "wifi", "wpa", "ssid")):
        return "wifi_protocol"
    if any(token in text for token in ("固件", "firmware", "ota", "更新", "update", "签名", "证书")):
        return "firmware_update"
    if any(token in text for token in ("命令注入", "command injection", "os命令")):
        return "command_injection"
    if any(token in text for token in ("媒体", "解析", "codec", "decoder", "overflow", "use-after-free", "uaf", "内存")):
        return "media_parser"
    if any(token in text for token in ("eop", "权限", "提权", "id", "信息泄露", "密钥")):
        return "local_privilege"
    return "application_input"


def classify_runtime(category: str, probe_kind: str, domain: str, component: str) -> tuple[str, list[str], list[str], list[str]]:
    if category == "wireless":
        if probe_kind == "bluetooth_protocol":
            return "bluetooth", ["bluetooth_mac"], ["bluetooth", "local_artifact"], ["android", "linux", "all"]
        return "wifi", ["interface"], ["wireless", "local_artifact"], ["android", "linux", "all"]
    if category == "advanced":
        return "local", ["software_inventory_text"], ["local_artifact", "system"], ["android", "linux", "qnx", "all"]
    if category == "network":
        if "usb" in f"{domain} {component}".lower() or "USB" in f"{domain} {component}":
            return "local", ["usb_mount_point"], ["local_artifact", "network"], ["all"]
        return "local", ["software_inventory_text"], ["local_artifact", "network"], ["all"]
    return "local", ["software_inventory_text"], ["application", "local_artifact"], ["android", "linux", "all"]


def sample_contract(probe_kind: str) -> tuple[str, str, tuple[str, ...]]:
    if probe_kind == "firmware_update":
        return ".upd", "firmware_update_sample_path", ("firmware_update_cmd", "update_validator_cmd", "decoder_cmd")
    if probe_kind == "command_injection":
        return ".manifest", "manifest_sample_path", ("update_validator_cmd", "parser_cmd", "decoder_cmd")
    if probe_kind == "bluetooth_protocol":
        return ".btsnoop", "bluetooth_sample_path", ("bluetooth_runner_cmd", "bt_replay_cmd", "decoder_cmd")
    if probe_kind == "wifi_protocol":
        return ".pcap", "wifi_sample_path", ("wifi_replay_cmd", "pcap_replay_cmd", "decoder_cmd")
    if probe_kind == "media_parser":
        return ".bin", "media_sample_path", ("media_decoder_cmd", "decoder_cmd", "parser_cmd")
    if probe_kind == "local_privilege":
        return ".json", "local_trigger_sample_path", ("local_validator_cmd", "aaos_probe_cmd", "decoder_cmd")
    return ".json", "application_sample_path", ("app_validator_cmd", "parser_cmd", "decoder_cmd")


def build_phenomenon(probe_kind: str, cve: str, component: str, vuln_type: str) -> str:
    return f"controlled {probe_kind} stimulus prepared for {cve} {component} {vuln_type} observation"


def build_operator_action(probe_kind: str) -> str:
    actions = {
        "firmware_update": "Run sample_path through an isolated firmware/update validator and observe rejected unsigned package, parser crash, restart, or command-boundary violation.",
        "command_injection": "Run sample_path through the vulnerable parser/update handler in a lab and observe command-boundary handling, crash, or explicit rejection.",
        "bluetooth_protocol": "Replay sample_path only on an authorized Bluetooth test bench and observe bluetoothd/service crash, disconnect, restart, or ASAN output.",
        "wifi_protocol": "Replay sample_path only on an authorized Wi-Fi lab interface and observe supplicant/driver crash, disconnect, or ASAN output.",
        "media_parser": "Run sample_path with the target media/parser command and observe crash, ASAN, process restart, or safe rejection.",
        "local_privilege": "Run sample_path with the local AAOS/BSP validator and observe privilege-boundary violation, denial, crash, or safe rejection.",
        "application_input": "Run sample_path with the target application parser/validator and observe crash, unauthorized state transition, or safe rejection.",
    }
    return actions.get(probe_kind, actions["application_input"])


def infer_attack_surface(domain: str, component: str, vuln_type: str) -> str:
    return " / ".join(part for part in (domain, component, vuln_type) if part)


def signature_tokens(*values: str) -> list[str]:
    tokens: list[str] = []
    for value in values:
        for token in re.split(r"[^A-Za-z0-9_.+-]+", value or ""):
            if len(token) >= 3 and token not in tokens:
                tokens.append(token)
    return tokens[:32]


def sanitize_identifier(value: str, max_parts: int = 8) -> str:
    parts = re.findall(r"[A-Za-z0-9]+", value)
    if not parts:
        return "Generated"
    cleaned = []
    for part in parts:
        normalized = part.lower()
        if cleaned and cleaned[-1].lower() == normalized:
            continue
        cleaned.append(part[:24])
        if len(cleaned) >= max_parts:
            break
    joined = "_".join(cleaned)
    if joined[0].isdigit():
        joined = f"Poc_{joined}"
    return joined


def normalize_severity(value: str) -> str:
    text = value.lower()
    if "critical" in text:
        return "Critical"
    if "high" in text:
        return "High"
    if "medium" in text:
        return "Medium"
    return "High"


def clean_text(value: Any) -> str:
    return str(value or "").strip()


def safe_lower(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def escape_for_py(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def python_repr(value: Any) -> str:
    return repr(value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xlsx", nargs="?", default=str(DEFAULT_XLSX))
    parser.add_argument("--write", action="store_true", help="Write generated plugin files")
    args = parser.parse_args()

    specs = build_plugin_specs(load_records(args.xlsx))
    if args.write:
        written = write_plugins(specs)
        for path in written:
            print(path.relative_to(SERVER_DIR.parent))
    else:
        for spec in specs:
            print(f"{spec.display_id} {spec.cve} -> {spec.output_path.relative_to(SERVER_DIR.parent)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

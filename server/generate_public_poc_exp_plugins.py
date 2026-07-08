#!/usr/bin/env python3
"""Generate safe active-validation plugins from public PoC/EXP workbook rows."""
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import openpyxl

from generate_xlsx_exp_plugins import (
    build_operator_action,
    build_phenomenon,
    build_stimulus_profile,
    clean_text,
    escape_for_py,
    normalize_severity,
    python_repr,
    render_sample_writer,
    safe_lower,
    sample_contract,
    sanitize_identifier,
    signature_tokens,
)


SERVER_DIR = Path(__file__).resolve().parent
POCS_DIR = SERVER_DIR / "pocs"
DEFAULT_XLSX = SERVER_DIR.parent.parent / "connected_vehicle_public_poc_exp_50.xlsx"


HEADERS = (
    "序号",
    "CVE编号",
    "年份",
    "类别",
    "产品/项目",
    "影响组件",
    "漏洞类型",
    "影响简述",
    "PoC/EXP状态",
    "PoC/EXP来源URL",
    "主公告/漏洞库URL",
    "车机相关性说明",
    "置信度",
)


PUBLIC_SOURCE_EVIDENCE: dict[str, list[dict[str, str]]] = {
    "CVE-2022-42005": [{
        "path": "server/public_poc_sources/repos/AnalyticETH__tesla-security-research/04-LOG-BACKSHELL-AND-DV-ACCESS.md",
        "artifact_type": "technical_reproduction",
        "trigger_summary": "svlogd config processor directive executes a replacement compression script during log rotation; prototype_server exposes data value access.",
        "safe_adaptation": "check log-rotation processor directives and prototype_server configuration without installing backshell scripts",
    }],
    "CVE-2022-42006": [{
        "path": "server/public_poc_sources/repos/AnalyticETH__tesla-security-research/04-LOG-BACKSHELL-AND-DV-ACCESS.md",
        "artifact_type": "technical_reproduction",
        "trigger_summary": "QtCarServer prototype_server websocket bypasses dbus access controls for data value get/set operations.",
        "safe_adaptation": "validate prototype_server exposure and websocket command boundary without mutating vehicle data values",
    }],
    "CVE-2022-42007": [{
        "path": "server/public_poc_sources/repos/AnalyticETH__tesla-security-research/02-EXPIRED-ODIN-TOKENS.md",
        "artifact_type": "technical_reproduction",
        "trigger_summary": "expired Toolbox tokens can generate ODIN tokens, then vehicle acceptance can be influenced by NTP spoofing.",
        "safe_adaptation": "inspect token expiry handling and NTP rollback observability without replaying credentials",
    }],
    "CVE-2022-42008": [{
        "path": "server/public_poc_sources/repos/AnalyticETH__tesla-security-research/01-ROOT-SHELL-VIA-ODIN.md",
        "artifact_type": "technical_reproduction",
        "trigger_summary": "ODIN TEST_DIGITAL-MICS_X_FUNCTIONAL-CHECK accepts MicTest-Input command list that flows into CID_EXEC.",
        "safe_adaptation": "submit or validate a benign echo command list only in authorized bench and require operator review",
    }],
    "CVE-2024-10382": [{
        "path": "server/public_poc_sources/pages/blog.calif.io_p_cve-2024-10382-arbitrary-code-execution.html",
        "artifact_type": "technical_article",
        "trigger_summary": "AndroidX CarAppService unsafe deserialization path can instantiate attacker-controlled classes from local app input.",
        "safe_adaptation": "use a non-executable serialized class marker to validate rejection path in AAOS app harness",
    }],
    "CVE-2017-13082": [{
        "path": "server/public_poc_sources/repos/vanhoefm__krackattacks-scripts/krackattack/krack-test-client.py",
        "artifact_type": "protocol_test_script",
        "trigger_summary": "KRACK client test replays handshake messages to observe key reinstallation behavior.",
        "safe_adaptation": "generate EAPOL replay metadata and require controlled RF lab execution",
    }],
    "CVE-2017-13084": [{
        "path": "server/public_poc_sources/repos/vanhoefm__krackattacks-scripts/krackattack/krack-test-client.py",
        "artifact_type": "protocol_test_script",
        "trigger_summary": "KRACK PeerKey/TDLS scenario reuses replayed key material during handshake handling.",
        "safe_adaptation": "model PeerKey replay counters without injecting frames outside an RF lab",
    }],
    "CVE-2017-13086": [{
        "path": "server/public_poc_sources/repos/vanhoefm__krackattacks-scripts/krackattack/krack-test-client.py",
        "artifact_type": "protocol_test_script",
        "trigger_summary": "KRACK TDLS tunneled direct-link setup peer key reinstall test logic.",
        "safe_adaptation": "emit TDLS replay-counter test vector for authorized RF validation",
    }],
    "CVE-2017-13087": [{
        "path": "server/public_poc_sources/repos/vanhoefm__krackattacks-poc-zerokey/krackattack/krack-all-zero-tk.py",
        "artifact_type": "protocol_test_script",
        "trigger_summary": "KRACK zero-key PoC observes group key reinstall behavior with controlled handshake replay.",
        "safe_adaptation": "represent WNM sleep GTK reinstall as lab-only EAPOL metadata",
    }],
    "CVE-2017-13088": [{
        "path": "server/public_poc_sources/repos/vanhoefm__krackattacks-poc-zerokey/krackattack/krack-all-zero-tk.py",
        "artifact_type": "protocol_test_script",
        "trigger_summary": "KRACK zero-key PoC covers IGTK reinstall observation during WNM sleep response handling.",
        "safe_adaptation": "represent IGTK reinstall as lab-only replay-counter metadata",
    }],
    "CVE-2020-26139": [{
        "path": "server/public_poc_sources/repos/vanhoefm__fragattacks/research/fragattack.py",
        "artifact_type": "protocol_test_script",
        "trigger_summary": "FragAttacks framework builds frames that test forwarding of EAPOL frames from unauthenticated senders.",
        "safe_adaptation": "emit fragment/EAPOL forwarding boundary manifest for isolated Wi-Fi lab",
    }],
    "CVE-2020-26140": [{
        "path": "server/public_poc_sources/repos/vanhoefm__fragattacks/research/fragattack.py",
        "artifact_type": "protocol_test_script",
        "trigger_summary": "FragAttacks tests acceptance of plaintext data frames in protected networks.",
        "safe_adaptation": "emit plaintext protected-network frame metadata for controlled AP/client validation",
    }],
    "CVE-2020-26141": [{
        "path": "server/public_poc_sources/repos/vanhoefm__fragattacks/research/tests_attacks.py",
        "artifact_type": "protocol_test_script",
        "trigger_summary": "FragAttacks test cases cover TKIP MIC verification on fragmented frames.",
        "safe_adaptation": "emit fragmented TKIP MIC boundary manifest only",
    }],
    "CVE-2020-26142": [{
        "path": "server/public_poc_sources/repos/vanhoefm__fragattacks/research/tests_attacks.py",
        "artifact_type": "protocol_test_script",
        "trigger_summary": "FragAttacks test cases cover processing fragmented frames as complete frames.",
        "safe_adaptation": "emit partial-fragment sequence manifest for isolated lab",
    }],
    "CVE-2020-26143": [{
        "path": "server/public_poc_sources/repos/vanhoefm__fragattacks/research/tests_attacks.py",
        "artifact_type": "protocol_test_script",
        "trigger_summary": "FragAttacks test cases cover fragmented plaintext data frame acceptance.",
        "safe_adaptation": "emit plaintext-fragment acceptance manifest",
    }],
    "CVE-2020-26144": [{
        "path": "server/public_poc_sources/repos/vanhoefm__fragattacks/research/tests_attacks.py",
        "artifact_type": "protocol_test_script",
        "trigger_summary": "FragAttacks test cases cover plaintext A-MSDU frames that start with RFC1042 headers.",
        "safe_adaptation": "emit RFC1042 A-MSDU boundary manifest",
    }],
    "CVE-2020-26145": [{
        "path": "server/public_poc_sources/repos/vanhoefm__fragattacks/research/tests_attacks.py",
        "artifact_type": "protocol_test_script",
        "trigger_summary": "FragAttacks test cases cover plaintext broadcast fragment acceptance.",
        "safe_adaptation": "emit broadcast-fragment manifest for RF lab",
    }],
    "CVE-2020-26146": [{
        "path": "server/public_poc_sources/repos/vanhoefm__fragattacks/research/tests_attacks.py",
        "artifact_type": "protocol_test_script",
        "trigger_summary": "FragAttacks test cases cover encrypted fragments with non-consecutive packet numbers.",
        "safe_adaptation": "emit non-consecutive packet-number fragment manifest",
    }],
    "CVE-2020-26147": [{
        "path": "server/public_poc_sources/repos/vanhoefm__fragattacks/research/tests_attacks.py",
        "artifact_type": "protocol_test_script",
        "trigger_summary": "FragAttacks test cases cover mixed encrypted/plaintext fragment reassembly.",
        "safe_adaptation": "emit mixed-encryption fragment manifest",
    }],
    "CVE-2019-9494": [{
        "path": "server/public_poc_sources/repos/vanhoefm__dragonslayer/README.md; server/public_poc_sources/repos/jabbaw0nky__DragonShift/dragonshift.py",
        "artifact_type": "protocol_test_script",
        "trigger_summary": "Dragonblood/DragonSlayer tooling tests SAE cache side-channel and Dragonfly exchange behavior.",
        "safe_adaptation": "emit SAE group/scalar timing test metadata without active RF attack",
    }],
    "CVE-2019-9496": [{
        "path": "server/public_poc_sources/repos/vanhoefm__dragonslayer/README.md; server/public_poc_sources/repos/jabbaw0nky__DragonShift/dragonshift.py",
        "artifact_type": "protocol_test_script",
        "trigger_summary": "Dragonblood tooling exercises SAE confirm/state validation edge cases.",
        "safe_adaptation": "emit SAE confirm-state boundary manifest",
    }],
    "CVE-2019-9498": [{
        "path": "server/public_poc_sources/repos/vanhoefm__dragonslayer/README.md; server/public_poc_sources/repos/jabbaw0nky__DragonShift/dragonshift.py",
        "artifact_type": "protocol_test_script",
        "trigger_summary": "Dragonblood tooling covers EAP-pwd scalar/element validation failures.",
        "safe_adaptation": "emit EAP-pwd invalid scalar/element manifest",
    }],
    "CVE-2020-12352": [{
        "path": "server/public_poc_sources/pages/google.github.io_security-research_pocs_linux_bleedingtooth.html",
        "artifact_type": "technical_article",
        "trigger_summary": "BleedingTooth PoC describes Linux Bluetooth A2MP/L2CAP information leak exploitation path.",
        "safe_adaptation": "emit Bluetooth A2MP boundary metadata and require lab-only validation",
    }],
    "CVE-2020-24490": [{
        "path": "server/public_poc_sources/pages/github.com_google_security-research_security_advisories_GHSA-ccx2-w2r4-x649.html",
        "artifact_type": "security_advisory",
        "trigger_summary": "Google advisory describes HCI extended advertising heap overflow conditions.",
        "safe_adaptation": "emit HCI extended advertising boundary metadata without sending frames by default",
    }],
    "CVE-2023-2002": [{
        "path": "server/public_poc_sources/repos/lrh2000__CVE-2023-2002/exp/bt_power.c",
        "artifact_type": "native_poc_source",
        "trigger_summary": "public exploit source drives Bluetooth HCI management command logic flaw.",
        "safe_adaptation": "compile/run only in isolated Bluetooth lab; default plugin emits management-command manifest",
    }],
    "CVE-2015-1538": [{
        "path": "server/public_poc_sources/repos/Fuzion24__cve-2015-1538-2/Stagefright_CVE-2015-1538-1_Exploit.py",
        "artifact_type": "exploit_source",
        "trigger_summary": "Python exploit builds MP4 stsc atom with integer-overflow sample-to-chunk table.",
        "safe_adaptation": "emit non-weaponized MP4 atom boundary manifest; no ROP or shell payload copied",
    }],
    "CVE-2015-3824": [{
        "path": "server/public_poc_sources/pages/www.exploit-db.com_exploits_40436.html",
        "artifact_type": "exploit_source_page",
        "trigger_summary": "Exploit-DB Stagefright tx3g Metasploit module describes paired tx3g chunks and integer overflow trigger.",
        "safe_adaptation": "emit tx3g atom boundary manifest; no Metasploit payload or ROP copied",
    }],
    "CVE-2015-3864": [{
        "path": "server/public_poc_sources/repos/Bhathiya404__Exploiting-Stagefright-Vulnerability-CVE-2015-3864/README.md; server/public_poc_sources/pages/www.exploit-db.com_exploits_40436.html",
        "artifact_type": "exploit_walkthrough",
        "trigger_summary": "Stagefright parseChunk/tx3g reproduction material describes malformed MP4 delivery and parser crash behavior.",
        "safe_adaptation": "emit malformed MP4 atom manifest for local decoder harness only",
    }],
    "CVE-2015-6620": [{
        "path": "server/public_poc_sources/repos/flankerhqd__CVE-2015-6620-POC/main.cpp",
        "artifact_type": "native_poc_source",
        "trigger_summary": "C++ PoC exercises Android mediaserver AMessage unmarshal arbitrary write condition.",
        "safe_adaptation": "emit AMessage parcel boundary manifest without arbitrary write primitive",
    }],
    "CVE-2023-45779": [{
        "path": "server/public_poc_sources/repos/metaredteam__rtx-cve-2023-45779/apex-checker/check.sh; server/public_poc_sources/repos/metaredteam__rtx-cve-2023-45779/apex-forger/repack.sh",
        "artifact_type": "checker_and_forge_scripts",
        "trigger_summary": "public toolkit checks Android APEX/APK signing keys and includes repack workflow for vulnerable test-key reuse.",
        "safe_adaptation": "run checker path only by default; forged APEX install remains manual lab-only",
    }],
    "CVE-2026-0006": [{
        "path": "server/public_poc_sources/repos/mobilehackinglab__CVE-2026-0006-openapv-poc/generate_overflow_mp4.py; server/public_poc_sources/repos/mobilehackinglab__CVE-2026-0006-openapv-poc/poc_mp4_asan.c",
        "artifact_type": "exploit_source",
        "trigger_summary": "PoC generator creates APV MP4 overflow sample and ASAN harness for codec boundary.",
        "safe_adaptation": "emit APV MP4 box boundary manifest; real generated sample only in isolated decoder lab",
    }],
    "CVE-2024-47538": [{
        "path": "server/public_poc_sources/pages/securitylab.github.com_advisories_GHSL-2024-115_GHSL-2024-118_Gstreamer.html",
        "artifact_type": "technical_advisory",
        "trigger_summary": "GitHub Security Lab advisory describes GStreamer stack buffer overflow parser boundary.",
        "safe_adaptation": "emit GStreamer caps/container boundary manifest for local gst-discoverer harness",
    }],
    "CVE-2024-47607": [{
        "path": "server/public_poc_sources/pages/securitylab.github.com_advisories_GHSL-2024-115_GHSL-2024-118_Gstreamer.html",
        "artifact_type": "technical_advisory",
        "trigger_summary": "GitHub Security Lab advisory describes GStreamer out-of-bounds write parser boundary.",
        "safe_adaptation": "emit GStreamer parser OOB write boundary manifest",
    }],
    "CVE-2024-47615": [{
        "path": "server/public_poc_sources/pages/securitylab.github.com_advisories_GHSL-2024-115_GHSL-2024-118_Gstreamer.html",
        "artifact_type": "technical_advisory",
        "trigger_summary": "GitHub Security Lab advisory describes GStreamer null pointer dereference DoS condition.",
        "safe_adaptation": "emit null-deref parser boundary manifest",
    }],
    "CVE-2024-47613": [{
        "path": "server/public_poc_sources/pages/securitylab.github.com_advisories_GHSL-2024-115_GHSL-2024-118_Gstreamer.html",
        "artifact_type": "technical_advisory",
        "trigger_summary": "GitHub Security Lab advisory describes GStreamer memory-safety parser condition.",
        "safe_adaptation": "emit memory-safety boundary manifest for local GStreamer harness",
    }],
}


@dataclass(frozen=True)
class PublicPluginSpec:
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
    public_poc_url: str
    references: list[str]
    research_value: str
    confidence: str
    attack_surface: str
    probe_kind: str
    sample_suffix: str
    sample_param: str
    command_params: tuple[str, ...]
    phenomenon: str
    operator_action: str
    signature_tokens: list[str]
    source_evidence: list[dict[str, str]]


def load_records(xlsx_path: str | Path = DEFAULT_XLSX) -> list[dict[str, Any]]:
    workbook = openpyxl.load_workbook(Path(xlsx_path), read_only=True, data_only=True)
    worksheet = workbook["公开PoC_EXP清单50"]
    rows = list(worksheet.iter_rows(values_only=True))
    headers = [str(item or "").strip() for item in rows[0]]
    records: list[dict[str, Any]] = []
    for row in rows[1:]:
        if not row or not row[0]:
            continue
        item = dict(zip(headers, row))
        records.append({key: item.get(key) for key in HEADERS})
    return records


def existing_cves() -> set[str]:
    cves: set[str] = set()
    for path in POCS_DIR.glob("**/*.py"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        if is_generated_public_plugin_text(text):
            continue
        cves.update(re.findall(r"CVE-\d{4}-\d{4,7}", text))
    return cves


def build_plugin_specs(records: list[dict[str, Any]], existing: set[str] | None = None) -> list[PublicPluginSpec]:
    existing = existing if existing is not None else existing_cves()
    next_numbers = existing_next_numbers()
    specs: list[PublicPluginSpec] = []
    seen_classes: set[str] = set()
    for record in records:
        cve = clean_text(record.get("CVE编号"))
        if not cve or cve in existing:
            continue
        row_id = int(record["序号"])
        year = int(record.get("年份") or 0)
        category_label = clean_text(record.get("类别"))
        vendor_product = clean_text(record.get("产品/项目"))
        component = clean_text(record.get("影响组件"))
        vuln_type = clean_text(record.get("漏洞类型"))
        summary = clean_text(record.get("影响简述"))
        poc_status = clean_text(record.get("PoC/EXP状态"))
        public_poc_url = clean_text(record.get("PoC/EXP来源URL"))
        source_url = clean_text(record.get("主公告/漏洞库URL"))
        research_value = clean_text(record.get("车机相关性说明"))
        confidence = clean_text(record.get("置信度"))
        category = classify_public_category(category_label, vendor_product, component, vuln_type, summary)
        probe_kind = classify_public_probe_kind(category, vendor_product, component, vuln_type, summary)
        protocol, required_params, profiles, target_os = classify_public_runtime(category, probe_kind, vendor_product, component)
        sample_suffix, sample_param, command_params = sample_contract(probe_kind)
        file_label = sanitize_identifier("_".join([vendor_product, component, vuln_type]), max_parts=7)
        file_number = next_numbers[category]
        next_numbers[category] += 1
        file_stem = f"{file_number:02d}_{file_label}_Audit"
        display_id = poc_display_id(category, file_number)
        class_name = poc_class_name(file_number, cve, vuln_type)
        while class_name in seen_classes:
            class_name = class_name.removesuffix("Plugin") + f"{len(seen_classes)}Plugin"
        seen_classes.add(class_name)
        references = split_urls(public_poc_url) + split_urls(source_url)
        specs.append(
            PublicPluginSpec(
                row_id=row_id,
                display_id=display_id,
                cve=cve,
                year=year,
                category=category,
                output_path=POCS_DIR / category / f"{file_stem}.py",
                class_name=class_name,
                file_stem=file_stem,
                poc_name=f"{cve} Public PoC/EXP Adapted Validation",
                severity=confidence_to_severity(confidence),
                protocol=protocol,
                required_params=required_params,
                profiles=profiles,
                target_os=target_os,
                vendor_product=vendor_product,
                component=component,
                vuln_type=vuln_type,
                summary=summary,
                poc_status=poc_status,
                source_url=source_url or public_poc_url,
                public_poc_url=public_poc_url,
                references=references,
                research_value=research_value,
                confidence=confidence,
                attack_surface=" / ".join(part for part in (category_label, component, vuln_type) if part),
                probe_kind=probe_kind,
                sample_suffix=sample_suffix,
                sample_param=sample_param,
                command_params=command_params,
                phenomenon=build_phenomenon(probe_kind, cve, component, vuln_type),
                operator_action=build_operator_action(probe_kind),
                signature_tokens=signature_tokens(cve, vendor_product, component, vuln_type, summary, poc_status),
                source_evidence=source_evidence_for(cve, public_poc_url, component, vuln_type),
            )
        )
    return specs


def render_plugin(spec: PublicPluginSpec) -> str:
    profile = build_stimulus_profile(spec)
    profile["public_poc_url"] = spec.public_poc_url
    profile["source_evidence"] = spec.source_evidence
    profile["adaptation_note"] = "PoC/EXP source adapted into a non-weaponized AutoSec lab stimulus with operator approval gates."
    return f'''#!/usr/bin/env python3
"""Public PoC/EXP adapted active-validation plugin for AutoSec Guard."""
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
        "poc_status": f"{spec.poc_status}; Public PoC/EXP source adapted for controlled validation; destructive trigger requires allow_disruptive=true",
        "research_value": spec.research_value,
        "source_url": spec.source_url,
        "public_poc_url": spec.public_poc_url,
        "references": spec.references,
        "source_evidence": spec.source_evidence,
        "requires_manual_review": True,
        "affected": [{"vendor": spec.vendor_product.split()[0] if spec.vendor_product else "Unknown", "product": spec.vendor_product, "versions": [{"version": "*", "status": "affected"}]}],
        "signature_tokens": spec.signature_tokens,
    })}


public_poc_profile = {python_repr(profile)}  # PoC/EXP source metadata and adaptation boundary.


def _write_generated_sample() -> str:
{render_source_backed_sample_writer(spec)}


def _public50_probe(plugin, vuln):
    return build_local_sample_probe(
        plugin,
        sample_param="{spec.sample_param}",
        command_params={python_repr(spec.command_params)},
        generated_sample=_write_generated_sample,
        phenomenon="{escape_for_py(spec.phenomenon)}",
        operator_action="{escape_for_py(spec.operator_action)} PoC/EXP source: {escape_for_py(spec.public_poc_url)}",
    )


class {spec.class_name}(IVIVulnerabilityPlugin):
    meta_generated_source = "public_poc_exp_50"
    meta_display_id = "{spec.display_id}"
    meta_poc_name = "{escape_for_py(spec.poc_name)}"
    meta_cve_id = "{spec.cve}"
    meta_severity = "{spec.severity}"
    meta_protocol = "{spec.protocol}"
    meta_target_os = {python_repr(spec.target_os)}
    meta_required_params = {python_repr(spec.required_params)}
    meta_profiles = {python_repr(spec.profiles)}
    meta_source_url = "{escape_for_py(spec.source_url or spec.public_poc_url)}"
    meta_attack_surface = "{escape_for_py(spec.attack_surface)}"
    is_disruptive = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_public50_probe)
'''


def source_evidence_for(cve: str, public_poc_url: str, component: str, vuln_type: str) -> list[dict[str, str]]:
    evidence = PUBLIC_SOURCE_EVIDENCE.get(cve)
    if evidence:
        return [dict(item) for item in evidence]
    return [{
        "path": public_poc_url,
        "artifact_type": "public_reference",
        "trigger_summary": f"Public reference for {component} {vuln_type}; no local source artifact mapping found.",
        "safe_adaptation": "metadata-only fallback; requires manual source review before native trigger use",
    }]


def render_source_backed_sample_writer(spec: PublicPluginSpec) -> str:
    safe_cve = safe_lower(spec.cve)
    content = "\n".join(source_adapted_manifest_lines(spec))
    return f'''    content = {python_repr(content)}
    return write_temp_text("{safe_cve}_public_source_", "{spec.sample_suffix}", content)'''


def source_adapted_manifest_lines(spec: PublicPluginSpec) -> list[str]:
    evidence = spec.source_evidence[0] if spec.source_evidence else {}
    lines = [
        "format=autosec-public-poc-adaptation-v1",
        f"cve={spec.cve}",
        f"product={spec.vendor_product}",
        f"component={spec.component}",
        f"vulnerability_type={spec.vuln_type}",
        f"public_source={spec.public_poc_url}",
        f"source_artifact={evidence.get('path', '')}",
        f"source_trigger={evidence.get('trigger_summary', '')}",
        f"safe_adaptation={evidence.get('safe_adaptation', '')}",
        "operator_boundary=do not replay weaponized public exploit against real vehicles; run only in authorized bench",
    ]
    cve = spec.cve
    if cve == "CVE-2022-42008":
        lines.extend([
            "source_field=ODIN task Model3/tasks/TEST_DIGITAL-MICS_X_FUNCTIONAL-CHECK",
            "source_param=MicTest-Input list passed to CID_EXEC",
            "adapted_payload=[\"/bin/echo\", \"AUTOSEC_ODIN_COMMAND_BOUNDARY_CHECK\"]",
            "expected=reject non-whitelisted command list or log blocked CID_EXEC invocation",
        ])
    elif cve == "CVE-2022-42007":
        lines.extend([
            "source_field=toolbox odin_token endpoint plus vehicle NTP trust boundary",
            "adapted_payload=expired-token-metadata-and-ntp-origin-timestamp-check",
            "expected=vehicle rejects expired ODIN token or flags time rollback",
        ])
    elif cve in {"CVE-2022-42005", "CVE-2022-42006"}:
        lines.extend([
            "source_field=svlogd config processor directive / prototype_server websocket",
            "adapted_payload=!/bin/echo AUTOSEC_LOG_ROTATION_BOUNDARY",
            "expected=integrity check detects executable log processor or prototype_server exposure",
        ])
    elif cve.startswith("CVE-2017-1308"):
        lines.extend([
            "source_field=KRACK EAPOL replay / key reinstall test-client harness",
            "adapted_payload=eapol_replay_counter=1; reinstall_key_marker=zero_or_duplicate_key_check",
            "expected=supplicant refuses replayed handshake or records no key reinstallation",
        ])
    elif cve.startswith("CVE-2020-261"):
        lines.extend([
            "source_field=FragAttacks fragmented/A-MSDU frame construction",
            "adapted_payload=fragment_sequence=mixed_plaintext_encrypted_boundary; amsdu_header=RFC1042",
            "expected=driver/AP drops malformed fragments without forwarding or reassembly",
        ])
    elif cve in {"CVE-2019-9494", "CVE-2019-9496", "CVE-2019-9498"}:
        lines.extend([
            "source_field=Dragonblood/DragonSlayer SAE/EAP-pwd state and scalar-element validation",
            "adapted_payload=dragonfly_group=19; scalar_element=invalid-or-side-channel-test-vector",
            "expected=hostapd/wpa_supplicant rejects invalid exchange and avoids cache-timing leak",
        ])
    elif cve in {"CVE-2020-12352", "CVE-2020-24490", "CVE-2023-2002"}:
        lines.extend([
            "source_field=Bluetooth L2CAP/A2MP/HCI management command boundary",
            "adapted_payload=bt_frame_type=A2MP/HCI; length_field=boundary; opcode=non-destructive-validation",
            "expected=kernel/BlueZ rejects malformed management frame without crash or info leak",
        ])
    elif cve in {"CVE-2015-1538", "CVE-2015-3824", "CVE-2015-3864", "CVE-2015-6620"}:
        lines.extend([
            "source_field=Android Stagefright MP4 atom parser",
            "adapted_payload=mp4_atoms=ftyp/moov/trak/stbl with stsc_or_tx3g_boundary_size",
            "expected=mediaserver/libstagefright rejects malformed atom or crashes only in isolated lab",
        ])
    elif cve == "CVE-2023-45779":
        lines.extend([
            "source_field=APEX/APK signing key reuse checker scripts",
            "adapted_payload=compare_apex_avb_key_fingerprint_against_known_test_keys",
            "expected=checker reports test-key reuse without installing forged APEX",
        ])
    elif cve == "CVE-2026-0006":
        lines.extend([
            "source_field=openapv overflow MP4 generator and codec ASAN PoC",
            "adapted_payload=apv_codec_box_length=boundary_overflow_marker; frame_count=1",
            "expected=decoder rejects sample or ASAN reports controlled overflow in lab",
        ])
    elif cve.startswith("CVE-2024-476") or cve == "CVE-2024-47538":
        lines.extend([
            "source_field=GStreamer Security Lab parser advisory and patch boundary",
            "adapted_payload=gstreamer_caps_or_container_field=boundary_length_marker",
            "expected=gst-discoverer/gst-launch rejects malformed media or crashes only in isolated lab",
        ])
    elif cve == "CVE-2024-10382":
        lines.extend([
            "source_field=AndroidX CarAppService deserialization route",
            "adapted_payload=serialized_intent_marker=non-executable-class-boundary",
            "expected=CarAppService rejects unexpected serialized class without code execution",
        ])
    return lines


def write_plugins(specs: list[PublicPluginSpec]) -> list[Path]:
    remove_existing_public_plugins()
    written: list[Path] = []
    for spec in specs:
        spec.output_path.parent.mkdir(parents=True, exist_ok=True)
        spec.output_path.write_text(render_plugin(spec), encoding="utf-8")
        written.append(spec.output_path)
    return written


def classify_public_category(category_label: str, vendor_product: str, component: str, vuln_type: str, summary: str) -> str:
    text = f"{category_label} {vendor_product} {component} {vuln_type} {summary}".lower()
    if any(token in text for token in ("wi-fi", "wifi", "wpa", "802.11", "bluetooth", "bluez", "l2cap", "hci", "hid")):
        return "wireless"
    if any(token in text for token in ("stagefright", "gstreamer", "libwebp", "codec", "media", "android", "aaos", "carappservice", "apex")):
        return "application"
    if any(token in text for token in ("tesla", "odin", "diagnostic", "firmware", "usb update", "updater", "token", "qtcarserver")):
        return "network"
    return "application"


def classify_public_probe_kind(category: str, vendor_product: str, component: str, vuln_type: str, summary: str) -> str:
    text = f"{vendor_product} {component} {vuln_type} {summary}".lower()
    if any(token in text for token in ("bluetooth", "bluez", "l2cap", "a2mp", "hci", "hid")):
        return "bluetooth_protocol"
    if any(token in text for token in ("wi-fi", "wifi", "wpa", "802.11", "krack", "fragattacks", "sae", "eap-pwd")):
        return "wifi_protocol"
    if any(token in text for token in ("firmware", "update", "updater", "usb update")):
        return "firmware_update"
    if any(token in text for token in ("command injection", "root shell", "log shell")):
        return "command_injection"
    if any(token in text for token in ("stagefright", "gstreamer", "codec", "media", "mp4", "parser", "overflow", "write", "uaf")):
        return "media_parser"
    if any(token in text for token in ("deserialization", "privilege", "token", "time spoofing", "apex", "permission")):
        return "local_privilege"
    return "application_input"


def classify_public_runtime(category: str, probe_kind: str, vendor_product: str, component: str) -> tuple[str, list[str], list[str], list[str]]:
    if category == "wireless":
        if probe_kind == "bluetooth_protocol":
            return "bluetooth", ["bluetooth_mac"], ["bluetooth", "local_artifact"], ["android", "linux", "all"]
        return "wifi", ["interface"], ["wireless", "local_artifact"], ["android", "linux", "all"]
    if category == "network":
        if "tesla" in vendor_product.lower() or "diagnostic" in component.lower():
            return "local", ["software_inventory_text"], ["network", "local_artifact"], ["linux", "all"]
        return "local", ["usb_mount_point"], ["network", "local_artifact"], ["all"]
    return "local", ["software_inventory_text"], ["application", "local_artifact"], ["android", "linux", "all"]


def existing_next_numbers() -> dict[str, int]:
    numbers = {}
    for category in ("application", "network", "wireless", "advanced"):
        max_seen = 0
        for path in (POCS_DIR / category).glob("*.py"):
            match = re.match(r"^(\d+)_", path.name)
            if not match:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if is_generated_public_plugin_text(text):
                continue
            max_seen = max(max_seen, int(match.group(1)))
        numbers[category] = max_seen + 1
    return numbers


def remove_existing_public_plugins() -> None:
    for category in ("application", "network", "wireless", "advanced"):
        for path in (POCS_DIR / category).glob("*.py"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            if is_generated_public_plugin_text(text):
                path.unlink()


def is_generated_public_plugin_text(text: str) -> bool:
    legacy_batch_prefix = "PUBLIC" + "50"
    return (
        "meta_generated_source = \"public_poc_exp_50\"" in text
        or "meta_generated_source = 'public_poc_exp_50'" in text
        or f"meta_display_id = \"{legacy_batch_prefix}-" in text
        or f"meta_display_id = '{legacy_batch_prefix}-" in text
        or f"class {legacy_batch_prefix.title()}_" in text
    )


def poc_display_id(category: str, file_number: int) -> str:
    prefix = {
        "application": "POC-APP",
        "network": "POC-NET",
        "wireless": "POC-WIRELESS",
        "advanced": "POC-ADV",
    }.get(category, "POC")
    return f"{prefix}-{file_number:03d}"


def poc_class_name(file_number: int, cve: str, vuln_type: str) -> str:
    cve_token = re.sub(r"[^0-9A-Za-z]+", "", cve)
    words = re.findall(r"[A-Za-z0-9]+", vuln_type)
    suffix = "".join(word[:1].upper() + word[1:] for word in words[:5]) or "PublicPoc"
    return f"Poc{file_number}{cve_token}{suffix}AuditPlugin"


def split_urls(value: str) -> list[str]:
    urls = []
    for item in re.split(r"\s*;\s*|\s+", value or ""):
        item = item.strip()
        if item.startswith("http") and item not in urls:
            urls.append(item)
    return urls


def confidence_to_severity(confidence: str) -> str:
    if "高" in confidence:
        return "High"
    return "Medium"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xlsx", nargs="?", default=str(DEFAULT_XLSX))
    parser.add_argument("--write", action="store_true", help="Write generated plugin files")
    args = parser.parse_args()
    specs = build_plugin_specs(load_records(args.xlsx), existing_cves())
    if args.write:
        for path in write_plugins(specs):
            print(path.relative_to(SERVER_DIR.parent))
    else:
        for spec in specs:
            print(f"{spec.display_id} {spec.cve} -> {spec.output_path.relative_to(SERVER_DIR.parent)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

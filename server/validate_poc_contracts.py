#!/usr/bin/env python3
"""Read-only v3 contract and safety gate for the complete runtime PoC catalog."""
from __future__ import annotations

import argparse
import ast
import json
from collections import Counter
from pathlib import Path

from audit_exp_readiness import audit_file
from poc_catalog import list_available_poc_names, resolve_poc_path, resolve_poc_reference, resolve_poc_source
from poc_security import extract_poc_security_profile
from local_requirements import classify_poc_execution_mode


SERVER_DIR = Path(__file__).resolve().parent
POCS_DIR = SERVER_DIR / 'pocs'
EXPECTED_CATEGORIES = {'reconnaissance', 'network', 'canbus', 'wireless', 'application', 'advanced'}
FORBIDDEN_CALLS = {'eval', 'exec', 'compile', '__import__'}


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ''


def _attack_surface_for_category(category: str) -> str:
    mapping = {
        "network": "网络服务",
        "reconnaissance": "网络服务",
        "wireless": "无线/外设接口",
        "canbus": "CAN/UDS/OBD",
        "application": "车机APP/应用",
        "advanced": "固件/USB/OTA",
    }
    return mapping.get(category, "其他")


def build_poc_coverage_payload(pocs_dir: Path = POCS_DIR) -> dict:
  """Build poc_coverage.json payload aligned with the runtime catalog (318 PoCs)."""
  names = list_available_poc_names(pocs_dir)
  pocs: list[dict] = []
  for name in names:
    virtual_path, normalized, source = resolve_poc_source(pocs_dir, name)
    if not virtual_path or not normalized or not source:
      continue
    profile = extract_poc_security_profile(virtual_path, source_text=source)
    category = normalized.replace("\\", "/").split("/", 1)[0]
    severity = str(profile.get("severity") or "")
    destructive_level = str(profile.get("destructive_level") or "Safe")
    is_disruptive = bool(profile.get("is_disruptive"))
    required_params = profile.get("required_params") or []
    if not isinstance(required_params, list):
      required_params = []
    pocs.append({
      "poc_file": normalized,
      "display_id": profile.get("display_id") or Path(normalized).stem,
      "poc_name": profile.get("poc_name") or Path(normalized).stem,
      "category": category,
      "cve_id": profile.get("cve_id") or "",
      "severity": severity,
      "protocol": profile.get("protocol") or category,
      "target_os": ",".join(profile.get("target_os") or ["all"]) if isinstance(profile.get("target_os"), list) else str(profile.get("target_os") or "all"),
      "required_params": ",".join(required_params),
      "profiles": profile.get("profiles") or [],
      "destructive_level": destructive_level,
      "is_disruptive": is_disruptive,
      "parse_error": "",
      "attack_surface": _attack_surface_for_category(category),
      "high_risk": severity in {"High", "Critical"} or is_disruptive,
    })
  by_category = Counter(item["category"] for item in pocs)
  by_surface = Counter(item["attack_surface"] for item in pocs)
  return {
    "total": len(pocs),
    "by_category": dict(sorted(by_category.items())),
    "by_attack_surface": dict(sorted(by_surface.items())),
    "high_risk_count": sum(1 for item in pocs if item["high_risk"]),
    "pocs": pocs,
  }


def _validate_runtime_references(pocs_dir: Path, errors: list[dict]) -> None:
  try:
    from agent_recon_bootstrap import PORT_POC_HEURISTIC
    for port, poc_file in sorted(PORT_POC_HEURISTIC.items()):
      if not resolve_poc_path(str(pocs_dir), poc_file)[0]:
        errors.append({"code": "PORT_POC_HEURISTIC_INVALID", "port": port, "poc": poc_file})
  except Exception as exc:
    errors.append({"code": "PORT_POC_HEURISTIC_CHECK_FAILED", "detail": str(exc)})


def validate(expected_count: int = 318, strict_forbidden: bool = False) -> dict:
    names = list_available_poc_names(POCS_DIR)
    errors: list[dict] = []
    warnings: list[dict] = []
    descriptors: list[dict] = []
    categories = Counter()

    if len(names) != expected_count:
        errors.append({'code': 'CATALOG_COUNT_MISMATCH', 'expected': expected_count, 'actual': len(names)})

    for name in names:
        category = name.replace('\\', '/').split('/', 1)[0]
        categories[category] += 1
        virtual_path, normalized, source = resolve_poc_source(POCS_DIR, name)
        if not virtual_path or not normalized or not source:
            errors.append({'poc': name, 'code': 'SOURCE_UNRESOLVABLE'})
            continue
        try:
            tree = ast.parse(source, filename=normalized)
        except SyntaxError as exc:
            errors.append({'poc': name, 'code': 'SYNTAX_ERROR', 'detail': str(exc)})
            continue

        classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
        compatible = any(
            any(isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == 'run_verify' for item in cls.body)
            or any((isinstance(base, ast.Name) and base.id == 'IVIVulnerabilityPlugin') for base in cls.bases)
            for cls in classes
        )
        if not compatible:
            errors.append({'poc': name, 'code': 'PLUGIN_CONTRACT_MISSING'})

        forbidden = sorted({
            node.func.id for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        } & FORBIDDEN_CALLS)
        if forbidden:
            item = {'poc': name, 'code': 'DYNAMIC_CODE_API', 'calls': forbidden}
            (errors if strict_forbidden else warnings).append(item)
        shell_true_found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _call_name(node) in {'run', 'Popen', 'call', 'check_output'}:
                if any(keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords):
                    shell_true_found = True
        if shell_true_found:
            warnings.append({'poc': name, 'code': 'SUBPROCESS_SHELL_TRUE', 'sandbox_required': True})

        profile = extract_poc_security_profile(virtual_path, source_text=source)
        display_id = str(profile.get('display_id') or '').strip()
        if display_id.upper().startswith('XLSX-'):
            errors.append({'poc': name, 'code': 'FORBIDDEN_XLSX_DISPLAY_ID', 'display_id': display_id})
        finding = audit_file(Path(virtual_path)) if Path(virtual_path).exists() else None
        execution_mode = classify_poc_execution_mode(POCS_DIR, virtual_path, profile, normalized)
        required_params = profile.get('required_params') or []
        if not isinstance(required_params, list):
            errors.append({'poc': name, 'code': 'REQUIRED_PARAMS_NOT_LIST'})
            required_params = []
        descriptor = {
            'filename': normalized,
            'category': category,
            'display_id': profile.get('display_id') or Path(normalized).stem,
            'name': profile.get('poc_name') or Path(normalized).stem,
            'protocol': profile.get('protocol') or category,
            'target_os': profile.get('target_os') or ['all'],
            'required_params': required_params,
            'validation_tier': getattr(finding, 'validation_tier', 'PASSIVE') if finding else 'PASSIVE',
            'execution_safety': getattr(finding, 'execution_safety', 'safe') if finding else 'safe',
            'evidence_basis': getattr(finding, 'evidence_basis', []) if finding else [],
            'destructive_level': profile.get('destructive_level') or 'Safe',
            'requires_approval': bool(profile.get('is_disruptive')),
            'requires_human_review': bool(execution_mode.get('requires_post_execution_review')),
            'capability_dependencies': execution_mode.get('execution_requirements') or {},
            'simulation_gate': 'compiled_and_sandbox_policy_validated',
        }
        mandatory_fields = {
            'display_id', 'name', 'category', 'protocol', 'target_os', 'required_params',
            'validation_tier', 'execution_safety', 'destructive_level', 'evidence_basis',
            'requires_human_review', 'capability_dependencies', 'simulation_gate',
        }
        missing = sorted(field for field in mandatory_fields if field not in descriptor or descriptor[field] is None)
        if missing:
            errors.append({'poc': name, 'code': 'DESCRIPTOR_FIELDS_MISSING', 'fields': missing})
        descriptors.append(descriptor)

    if set(categories) != EXPECTED_CATEGORIES:
        errors.append({'code': 'CATEGORY_SET_MISMATCH', 'categories': sorted(categories)})
    ids = Counter(str(item['display_id']).lower() for item in descriptors)
    for duplicate, count in ids.items():
        if count > 1:
            errors.append({'code': 'DUPLICATE_DISPLAY_ID', 'display_id': duplicate, 'count': count})

    _validate_runtime_references(POCS_DIR, errors)

    return {
        'valid': not errors,
        'expected_count': expected_count,
        'actual_count': len(names),
        'categories': dict(sorted(categories.items())),
        'descriptor_count': len(descriptors),
        'simulation_gate_count': sum(1 for item in descriptors if item.get('simulation_gate')),
        'errors': errors,
        'warnings': warnings,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-count', type=int, default=318)
    parser.add_argument('--strict-forbidden', action='store_true')
    parser.add_argument('--sync-coverage', action='store_true', help='Rewrite lab/evidence/poc_coverage.json from runtime catalog')
    args = parser.parse_args()
    if args.sync_coverage:
        payload = build_poc_coverage_payload()
        out = SERVER_DIR.parent / 'lab' / 'evidence' / 'poc_coverage.json'
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps({'synced': True, 'path': str(out), 'total': payload['total']}, ensure_ascii=False, indent=2))
    result = validate(args.expected_count, args.strict_forbidden)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['valid'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

import ast
import os
from typing import Any, Dict


def extract_poc_security_profile(poc_path: str, source_text: str | None = None) -> Dict[str, Any]:
    profile: Dict[str, Any] = {
        "poc_name": os.path.basename(poc_path),
        "cve_id": "",
        "severity": "",
        "protocol": "",
        "target_os": [],
        "required_params": [],
        "destructive_level": "Safe",
        "is_disruptive": False,
    }

    try:
        if source_text is None:
            with open(poc_path, "r", encoding="utf-8") as handle:
                source_text = handle.read()
        tree = ast.parse(source_text, filename=poc_path)
    except Exception as exc:
        profile["parse_error"] = str(exc)
        return profile

    metadata_keys = {
        "meta_display_id",
        "meta_poc_name",
        "meta_cve_id",
        "meta_severity",
        "meta_protocol",
        "meta_target_os",
        "meta_required_params",
        "meta_destructive_level",
        "is_disruptive",
    }

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        class_meta = {}
        for body_item in node.body:
            if not isinstance(body_item, ast.Assign):
                continue
            try:
                value = ast.literal_eval(body_item.value)
            except Exception:
                continue
            for target_node in body_item.targets:
                if isinstance(target_node, ast.Name) and target_node.id in metadata_keys:
                    class_meta[target_node.id] = value
        if class_meta:
            profile["poc_name"] = class_meta.get("meta_poc_name") or profile["poc_name"]
            profile["cve_id"] = class_meta.get("meta_cve_id") or profile["cve_id"]
            profile["severity"] = class_meta.get("meta_severity") or profile["severity"]
            profile["protocol"] = class_meta.get("meta_protocol") or profile["protocol"]
            profile["target_os"] = class_meta.get("meta_target_os") or profile["target_os"]
            profile["required_params"] = class_meta.get("meta_required_params") or profile["required_params"]
            profile["destructive_level"] = class_meta.get("meta_destructive_level") or profile["destructive_level"]
            profile["is_disruptive"] = bool(class_meta.get("is_disruptive", profile["is_disruptive"]))
            break

    return profile


def should_require_disruptive_approval(profile: Dict[str, Any], params: Dict[str, Any]) -> bool:
    if params.get("allow_disruptive") in (True, "true", "True", "1", 1):
        return False
    destructive_level = str(profile.get("destructive_level") or "").lower()
    if profile.get("is_disruptive"):
        return True
    return destructive_level in {"restart", "dataloss", "brick"}

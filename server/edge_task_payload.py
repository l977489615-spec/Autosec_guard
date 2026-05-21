import os

from poc_catalog import resolve_poc_path


def attach_poc_code_to_task_payload(pocs_dir: str, task_payload: dict, poc_filename: str) -> dict:
    enriched = dict(task_payload)
    include_code = (os.environ.get("AUTOSEC_EDGE_INCLUDE_POC_CODE") or "").strip().lower()
    if include_code not in {"1", "true", "yes"}:
        return enriched
    poc_path, _ = resolve_poc_path(pocs_dir, poc_filename)
    if poc_path and os.path.exists(poc_path):
        with open(poc_path, "r", encoding="utf-8") as handle:
            enriched["poc_code"] = handle.read()
    return enriched

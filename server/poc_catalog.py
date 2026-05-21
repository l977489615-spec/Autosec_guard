import os


def resolve_poc_path(pocs_dir: str, poc_filename: str) -> tuple[str | None, str | None]:
    if not poc_filename:
        return None, None

    poc_path = os.path.join(pocs_dir, poc_filename)
    if os.path.exists(poc_path):
        return poc_path, os.path.relpath(poc_path, pocs_dir)

    basename = os.path.basename(poc_filename)
    for dirpath, _, filenames in os.walk(pocs_dir):
        if basename in filenames:
            poc_path = os.path.join(dirpath, basename)
            return poc_path, os.path.relpath(poc_path, pocs_dir)

    return None, None

import os
import re

# =================================================================
# AutoSec Guard - PoC Re-enumeration & Standardization Script
# This script renames PoC files sequentially and updates all 
# internal/external references (metadata, constants.ts).
# =================================================================

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
POCS_DIR = os.path.join(PROJECT_ROOT, "server", "pocs")
CONSTANTS_PATH = os.path.join(PROJECT_ROOT, "client", "constants.ts")

# 1. Define the desired order by category
CATEGORIES = ["reconnaissance", "network", "canbus", "wireless", "application", "advanced"]

def get_all_pocs():
    all_pocs = []
    for cat in CATEGORIES:
        cat_path = os.path.join(POCS_DIR, cat)
        if not os.path.exists(cat_path):
            continue
        files = [f for f in os.listdir(cat_path) if f.endswith(".py") and not f.startswith("__")]
        # Sort by their current numeric prefix
        files.sort(key=lambda x: int(x.split("_")[0]) if x[0].isdigit() else 999)
        for f in files:
            all_pocs.append({
                "category": cat,
                "old_name": f,
                "old_rel_path": f"{cat}/{f}"
            })
    return all_pocs

def run_migration():
    pocs = get_all_pocs()
    print(f"[*] Found {len(pocs)} PoCs to migrate.")
    
    mapping = {} # old_rel_path -> new_rel_path
    
    # Generate new names
    for i, poc in enumerate(pocs, 1):
        new_id = f"{i:02d}"
        # Remove old ID prefix from filename
        name_part = re.sub(r"^\d+_", "", poc["old_name"])
        poc["new_name"] = f"{new_id}_{name_part}"
        poc["new_rel_path"] = f"{poc['category']}/{poc['new_name']}"
        mapping[poc["old_rel_path"]] = poc["new_rel_path"]
        print(f"    [Plan] {poc['old_rel_path']} -> {poc['new_rel_path']}")

    # 2. Update files on disk (Renaming)
    # Strategy: Rename to temporary names first to avoid collisions if multiple passes are needed
    # But since we are moving across categories or just shifting up, we can just do it carefully.
    
    # Sort backwards to avoid overwriting if shifting up in the same dir
    for poc in reversed(pocs):
        old_full = os.path.join(POCS_DIR, poc["old_rel_path"])
        new_full = os.path.join(POCS_DIR, poc["new_rel_path"])
        
        if old_full == new_full:
            continue
            
        print(f"[*] Renaming file: {poc['old_rel_path']} -> {poc['new_rel_path']}")
        os.rename(old_full, new_full)

    # 3. Update Internal Content (Docstrings/Logger)
    for poc in pocs:
        file_path = os.path.join(POCS_DIR, poc["new_rel_path"])
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            
        # Update "Usage: python3 XX_..."
        old_prefix = poc["old_name"].split("_")[0]
        new_prefix = poc["new_name"].split("_")[0]
        
        # Replace occurrences of old filename with new filename in docstring/comments
        content = content.replace(poc["old_name"], poc["new_name"])
        
        # Replace "PoC Name: XX_..." or similar patterns if they exist
        # We also specifically look for "Usage: python3 12_..." etc.
        content = re.sub(r"(python3\s+)(\d+)(_)", rf"\g<1>{new_prefix}\g<3>", content)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

    # 4. Update client/constants.ts
    if os.path.exists(CONSTANTS_PATH):
        print(f"[*] Updating {CONSTANTS_PATH}...")
        with open(CONSTANTS_PATH, "r", encoding="utf-8") as f:
            ts_content = f.read()
            
        for old_rel, new_rel in mapping.items():
            # Match pocFile: 'category/XX_filename.py'
            ts_content = ts_content.replace(f"pocFile: '{old_rel}'", f"pocFile: '{new_rel}'")
            # Also catch double quotes just in case
            ts_content = ts_content.replace(f'pocFile: "{old_rel}"', f'pocFile: "{new_rel}"')

        with open(CONSTANTS_PATH, "w", encoding="utf-8") as f:
            f.write(ts_content)
        print("[+] constants.ts updated successfully.")

    print("\n[SUCCESS] All PoCs re-enumerated and synchronized!")

if __name__ == "__main__":
    run_migration()

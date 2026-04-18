#!/usr/bin/env python3
import json
import sys
from pathlib import Path

def add_root_component(sbom_file: str, app_name: str, app_version: str = "1.0.0"):
    path = Path(sbom_file)
    with path.open() as f:
        sbom = json.load(f)

    # add root component if not already present
    if "metadata" not in sbom:
        sbom["metadata"] = {}
    if "component" not in sbom["metadata"]:
        sbom["metadata"]["component"] = {
            "bom-ref": app_name,
            "type": "application",
            "name": app_name,
            "version": app_version
        }

    # ensure dependencies exist
    deps = sbom.setdefault("dependencies", [])

    # collect all refs
    all_refs = {d.get("ref") for d in deps}
    all_children = {c for d in deps for c in d.get("dependsOn", [])}

    # top-level components = those that never appear as a child
    top_level = [ref for ref in all_refs if ref and ref not in all_children]

    # add root only once
    if not any(d.get("ref") == app_name for d in deps):
        deps.insert(0, {"ref": app_name, "dependsOn": top_level})

    with path.open("w") as f:
        json.dump(sbom, f, indent=2)

    print(f"[INFO] Root component '{app_name}' added with {len(top_level)} top-level dependencies to {sbom_file}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: add_root_to_sbom.py <sbom_Platoo_test.json> <app_name> [<app_version>]")
        sys.exit(1)

    sbom_file = sys.argv[1]
    app_name = sys.argv[2]
    app_version = sys.argv[3] if len(sys.argv) > 3 else "1.0.0"
    add_root_component(sbom_file, app_name, app_version)

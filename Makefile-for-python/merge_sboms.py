#!/usr/bin/env python3
import json
import sys
from pathlib import Path

def normalize_license(licenses):
    """
    Normalize license fields into CycloneDX-compliant format:
    - ["MIT"]  -> [{ "license": { "id": "MIT" } }]
    - {"license": {"id": "Apache-2.0"}} is left as is
    - None -> []
    """
    out = []
    if not licenses:
        return out
    if isinstance(licenses, (list, tuple)):
        for lic in licenses:
            if isinstance(lic, str):
                out.append({"license": {"id": lic}})
            elif isinstance(lic, dict) and "license" in lic:
                out.append(lic)
            elif isinstance(lic, dict):
                # other keys such as licenseId or name
                lic_id = lic.get("licenseId") or lic.get("id") or lic.get("name")
                if lic_id:
                    out.append({"license": {"id": lic_id}})
    elif isinstance(licenses, str):
        out.append({"license": {"id": licenses}})
    return out

def merge_sboms(req_file, env_file, out_file, app_name="platoo-app", app_version="1.0.0"):
    with open(req_file) as f:
        sbom_req = json.load(f)
    with open(env_file) as f:
        sbom_env = json.load(f)

    components = {}
    dependencies = []

    # --- merge components ---
    for src, sbom in (("req", sbom_req), ("env", sbom_env)):
        for comp in sbom.get("components", []):
            bom_ref = comp.get("bom-ref") or comp.get("purl") or comp.get("name")
            if not bom_ref:
                continue
            # filter out synthetic requirements-L* entries
            if str(bom_ref).startswith("requirements-L"):
                continue
            # normalize license
            comp["licenses"] = normalize_license(comp.get("licenses"))
            components[bom_ref] = comp

        for dep in sbom.get("dependencies", []):
            ref = dep.get("ref")
            if ref and not str(ref).startswith("requirements-L"):
                dependencies.append(dep)

    # --- add root component ---
    root_ref = app_name
    metadata = {
        "component": {
            "bom-ref": root_ref,
            "type": "application",
            "name": app_name,
            "version": app_version
        }
    }

    # determine top-level refs (nodes that are not children of any other)
    all_refs = {d.get("ref") for d in dependencies}
    all_children = {c for d in dependencies for c in d.get("dependsOn", [])}
    top_level = [r for r in all_refs if r and r not in all_children]

    # insert root dependency
    dependencies.insert(0, {"ref": root_ref, "dependsOn": top_level})

    # --- final BOM ---
    merged = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": metadata,
        "components": list(components.values()),
        "dependencies": dependencies,
    }

    with open(out_file, "w") as f:
        json.dump(merged, f, indent=2)

    print(f"[INFO] Merged SBOM written to {out_file} with {len(components)} components and {len(dependencies)} dependencies")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: merge_sboms.py <sbom_req.json> <sbom_env.json> <out.json>")
        sys.exit(1)
    merge_sboms(sys.argv[1], sys.argv[2], sys.argv[3])

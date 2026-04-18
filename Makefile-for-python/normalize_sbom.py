#!/usr/bin/env python3
import json
import sys
from pathlib import Path

# Mapping from Trove classifiers to SPDX
TROVE_TO_SPDX = {
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
}

def normalize_license_list(licenses, comp_name="UNKNOWN"):
    out = []
    seen = set()
    if not licenses:
        return out

    for lic in licenses:
        if isinstance(lic, str):
            spdx = TROVE_TO_SPDX.get(lic, lic)
            entry = {"license": {"id": spdx}} if spdx in TROVE_TO_SPDX.values() else {"license": {"name": spdx}}
        elif isinstance(lic, dict):
            inner = lic.get("license", lic)
            lic_id = inner.get("id") or inner.get("licenseId") or inner.get("name")
            if not lic_id:
                continue
            spdx = TROVE_TO_SPDX.get(lic_id, lic_id)
            if spdx in TROVE_TO_SPDX.values() or spdx.isupper():
                entry = {"license": {"id": spdx}}
            else:
                entry = {"license": {"name": spdx}}
        else:
            continue

        key = json.dumps(entry, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(entry)
        else:
            print(f"[WARN] Duplicate license removed for {comp_name}: {entry}")

    return out

def normalize_url(url):
    if not url or str(url).strip().upper() == "UNKNOWN":
        return None
    if str(url).startswith("http://") or str(url).startswith("https://"):
        return url
    return None  # drop everything else

def normalize_version(version):
    if not version:
        return version
    v = str(version)
    v = v.replace("rc", "-rc").replace(".post", "-post")
    return v

def normalize_sbom(in_file, out_file):
    with open(in_file) as f:
        sbom = json.load(f)

    for comp in sbom.get("components", []):
        name = comp.get("name", "UNKNOWN")

        # remove evidence.licenses
        if "evidence" in comp and "licenses" in comp["evidence"]:
            print(f"[INFO] Removing evidence.licenses from {name}")
            comp["evidence"].pop("licenses", None)
            if not comp["evidence"]:
                comp.pop("evidence")

        # normalize licenses
        comp["licenses"] = normalize_license_list(comp.get("licenses"), name)

        # normalize URL
        if "url" in comp:
            new_url = normalize_url(comp["url"])
            if not new_url and "url" in comp:
                print(f"[INFO] Removing invalid URL from {name}: {comp['url']}")
                comp.pop("url")
            elif new_url:
                comp["url"] = new_url

        # normalize version
        if "version" in comp:
            comp["version"] = normalize_version(comp["version"])

    with open(out_file, "w") as f:
        json.dump(sbom, f, indent=2)

    print(f"[INFO] Normalized SBOM written to {out_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: normalize_sbom.py <in_sbom.json> <out_sbom.json>")
        sys.exit(1)
    normalize_sbom(sys.argv[1], sys.argv[2])

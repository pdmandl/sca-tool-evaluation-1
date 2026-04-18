#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SBOM Pipeline Tool (CycloneDX 1.4) - for pip projects.

Workflow:
1) Merge: requirements SBOM (better licenses) + environment SBOM (deps/graph).
2) Derive direct dependencies NOT from requirements but from the ENV graph:
   direct = nodes with in-degree 0 (appear as 'ref', never as 'dependsOn').
3) Add a root component + add root -> direct edges.
4) Set level (0=app, 1=direct, >=2=transitive) as properties[name=analysis:level].
5) Normalize licenses (Trove -> SPDX), remove metadata.tools.
6) Write final SBOM + validate with check-jsonschema, propagate exit code.
"""

import sys
import json
import datetime
import re
import subprocess
from typing import Dict, Any, List, Union, Set, Tuple

# === Configuration ===
CYCLONEDX_SCHEMA_URL = "https://cyclonedx.org/schema/bom-1.4.schema.json"
VALIDATION_LOG = "sbom_validation.log"

SAFE_SPDX_IDS = {
    "MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "MPL-2.0",
    "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
    "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "PSF-2.0", "Python-2.0"
}

TROVE_TO_SPDX = {
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.1-or-later",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
}

RE_TROVE = re.compile(r"::")


def _as_spdx_id_or_name(s: str) -> Dict[str, Any]:
    if not isinstance(s, str):
        return {}
    s = s.strip()
    if not s:
        return {}
    if s in TROVE_TO_SPDX:
        mapped = TROVE_TO_SPDX[s]
        if mapped in SAFE_SPDX_IDS:
            return {"license": {"id": mapped}}
        return {"license": {"name": mapped}}
    if RE_TROVE.search(s):
        return {"license": {"name": s}}
    if s in SAFE_SPDX_IDS:
        return {"license": {"id": s}}
    return {"license": {"name": s}}


def _normalize_license_entry(entry: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    if isinstance(entry, str):
        return _as_spdx_id_or_name(entry)
    if isinstance(entry, dict):
        expr = entry.get("expression")
        if isinstance(expr, str) and expr.strip():
            return {"expression": expr.strip()}
        lic_obj = entry.get("license", entry)
        if isinstance(lic_obj, dict):
            lic_obj = {k: v for k, v in lic_obj.items() if k not in {"acknowledgement"}}
            spdx_id = lic_obj.get("id") or lic_obj.get("licenseId")
            name = lic_obj.get("name")
            if isinstance(spdx_id, str) and spdx_id.strip():
                return _as_spdx_id_or_name(spdx_id.strip())
            if isinstance(name, str) and name.strip():
                return _as_spdx_id_or_name(name.strip())
        return {}
    return {}


def _normalize_license_list(raw_list: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw_list, list):
        return []
    out: List[Dict[str, Any]] = []
    for e in raw_list:
        choice = _normalize_license_entry(e)
        if choice:
            if ("license" in choice and isinstance(choice["license"], dict)
                and set(choice["license"].keys()) <= {"id", "name"}):
                out.append(choice)
            elif "expression" in choice and isinstance(choice["expression"], str):
                out.append(choice)
    return out


class SBOMPipeline:
    def __init__(self, sbom_req: str, sbom_env: str, sbom_out: str, app_name: str, app_version: str):
        self.sbom_req = sbom_req
        self.sbom_env = sbom_env
        self.sbom_out = sbom_out
        self.app_name = app_name
        self.app_version = app_version

    # ---------------- core ----------------

    def run(self) -> None:
        bom = self.merge_sboms()

        # derive direct refs ONLY from the ENV graph (robust)
        direct_refs = self._compute_direct_refs_from_env(bom)

        # add root + root->direct edges
        bom = self.add_root_component(bom, direct_refs)

        # BFS and level annotation (properties)
        root_ref = f"{self.app_name}:{self.app_version}"
        bom = self.annotate_levels(bom, root_ref, direct_refs)

        # normalize, write, validate
        bom = self.normalize(bom)
        self.write(bom)
        self.validate_or_exit()

    # ---------------- merge ----------------

    def merge_sboms(self) -> Dict[str, Any]:
        with open(self.sbom_req, "r", encoding="utf-8") as f:
            req = json.load(f)
        with open(self.sbom_env, "r", encoding="utf-8") as f:
            env = json.load(f)

        # map purl -> req-component (for better licenses/evidence)
        req_map = {c.get("purl"): c for c in req.get("components", []) if c.get("purl")}
        merged_components: List[Dict[str, Any]] = []

        for c in env.get("components", []):
            purl = c.get("purl")
            if purl and purl in req_map:
                c_req = req_map[purl]
                if c_req.get("licenses"):
                    c["licenses"] = c_req.get("licenses")
                if c_req.get("evidence"):
                    ev = dict(c.get("evidence") or {})
                    for k, v in c_req.get("evidence", {}).items():
                        ev.setdefault(k, v)
                    c["evidence"] = ev
            merged_components.append(c)

        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": merged_components,
            "dependencies": env.get("dependencies", []),
            "metadata": env.get("metadata", {}) or {},
        }
        # clean BOM root from ENV if needed: we set our root explicitly later
        if "component" in bom.get("metadata", {}):
            # leave as is - will be overwritten once add_root_component is called
            pass
        return bom

    # ---------------- direct refs from ENV graph ----------------

    def _compute_direct_refs_from_env(self, bom: Dict[str, Any]) -> List[str]:
        """
        Determine direct dependencies as nodes with in-degree 0 in the ENV graph.
        Operates on the 'ref'/'dependsOn' strings (typically 'Name==Version').
        """
        deps = bom.get("dependencies", []) or []
        parent_refs: Set[str] = set()
        child_refs: Set[str] = set()
        for d in deps:
            if not isinstance(d, dict):
                continue
            r = d.get("ref") or d.get("bom-ref") or d.get("bomRef")
            if not r:
                continue
            parent_refs.add(r)
            for ch in d.get("dependsOn", []) or []:
                child_refs.add(ch)

        # nodes that are never a child => direct dependencies
        direct = parent_refs - child_refs

        # only allow real components (with bom-ref)
        comp_refs = {c.get("bom-ref") for c in bom.get("components", []) if c.get("bom-ref")}
        direct = [r for r in direct if r in comp_refs]

        # (optional) emit sorted - stable
        direct_sorted = sorted(direct)
        print(f"[INFO] Direct refs from ENV graph: {len(direct_sorted)}")
        return direct_sorted

    # ---------------- root ----------------

    def add_root_component(self, bom: Dict[str, Any], direct_refs: List[str]) -> Dict[str, Any]:
        root_ref = f"{self.app_name}:{self.app_version}"
        root = {
            "type": "application",
            "name": self.app_name,
            "version": self.app_version,
            "bom-ref": root_ref,
        }
        bom.setdefault("components", []).append(root)

        ts = (
            datetime.datetime.now(datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        meta = dict(bom.get("metadata", {}) or {})
        meta["timestamp"] = ts
        meta["component"] = root
        bom["metadata"] = meta

        deps = bom.setdefault("dependencies", [])
        if not any(isinstance(d, dict) and d.get("ref") == root_ref for d in deps):
            deps.append({"ref": root_ref, "dependsOn": list(direct_refs)})
        else:
            # ensure we actually attach the direct_refs (no duplicates)
            for d in deps:
                if d.get("ref") == root_ref:
                    exists = set(d.get("dependsOn", []) or [])
                    d["dependsOn"] = sorted(exists | set(direct_refs))
                    break

        return bom

    # ---------------- annotate levels ----------------

    def annotate_levels(self, bom: Dict[str, Any], root_ref: str, direct_refs: List[str]) -> Dict[str, Any]:
        comp_map = {c.get("bom-ref"): c for c in bom.get("components", []) if c.get("bom-ref")}
        dep_map = {d["ref"]: d.get("dependsOn", []) for d in bom.get("dependencies", []) if "ref" in d}

        # BFS starting at root
        visited: Dict[str, int] = {}
        queue: List[Tuple[str, int]] = [(root_ref, 0)]
        while queue:
            ref, lvl = queue.pop(0)
            if ref in visited and visited[ref] <= lvl:
                continue
            visited[ref] = lvl
            for child in dep_map.get(ref, []):
                queue.append((child, lvl + 1))

        # assign levels:
        # - root = 0
        # - nodes in direct_refs = 1 (in case BFS would set them >1 via intermediate nodes)
        # - all others: BFS level; if unreachable, conservatively set to 2
        for ref, comp in comp_map.items():
            lvl = visited.get(ref)
            if ref in direct_refs:
                lvl = 1
            if ref == root_ref:
                lvl = 0
            if lvl is None:
                lvl = 2  # not attached to the root graph - classify as transitive

            # replace old property, do not duplicate
            props = [p for p in (comp.get("properties") or []) if p.get("name") != "analysis:level"]
            props.append({"name": "analysis:level", "value": str(lvl)})
            comp["properties"] = props

        # short diagnostic
        direct_count = sum(1 for c in comp_map.values() for p in (c.get("properties") or [])
                           if p.get("name") == "analysis:level" and p.get("value") == "1")
        trans_count = sum(1 for c in comp_map.values() for p in (c.get("properties") or [])
                          if p.get("name") == "analysis:level" and p.get("value") not in ("0", "1"))
        print(f"[INFO] Annotated levels → direct={direct_count}, transitive={trans_count}")
        return bom

    # ---------------- normalize ----------------

    def normalize(self, bom: Dict[str, Any]) -> Dict[str, Any]:
        # remove tools (otherwise causes validation issues)
        if "metadata" in bom:
            bom["metadata"].pop("tools", None)

        # normalize licenses
        for comp in bom.get("components", []):
            if "licenses" in comp:
                cleaned = _normalize_license_list(comp.get("licenses"))
                if cleaned:
                    comp["licenses"] = cleaned
                else:
                    comp.pop("licenses", None)

            ev = comp.get("evidence")
            if isinstance(ev, dict) and "licenses" in ev:
                ev_clean = _normalize_license_list(ev.get("licenses"))
                if ev_clean:
                    ev["licenses"] = ev_clean
                else:
                    ev.pop("licenses", None)

        return bom

    # ---------------- IO/validate ----------------

    def write(self, bom: Dict[str, Any]) -> None:
        with open(self.sbom_out, "w", encoding="utf-8") as f:
            json.dump(bom, f, indent=2, ensure_ascii=False)
        print(f"[INFO] Final SBOM written to {self.sbom_out}")

    def validate_or_exit(self) -> None:
        cmd = ["check-jsonschema", "--schemafile", CYCLONEDX_SCHEMA_URL, self.sbom_out]
        with open(VALIDATION_LOG, "w", encoding="utf-8") as logf:
            proc = subprocess.run(cmd, stdout=logf, stderr=subprocess.STDOUT)
            ec = proc.returncode

        if ec == 0:
            print(f"[INFO] SBOM validation OK (exit {ec}).")
        else:
            print(f"[ERROR] SBOM validation failed (exit {ec}).")
        print(f"[INFO] Look into VALIDATION_LOG: {VALIDATION_LOG}")
        sys.exit(ec)

    @staticmethod
    def main(argv: List[str]):
        if len(argv) != 6:
            print("Usage: python sbom_validation_pipeline.py <sbom_req.json> <sbom_env.json> <output.json> <app_name> <app_version>")
            sys.exit(1)
        _, sbom_req, sbom_env, sbom_out, app_name, app_version = argv
        SBOMPipeline(sbom_req, sbom_env, sbom_out, app_name, app_version).run()


if __name__ == "__main__":
    SBOMPipeline.main(sys.argv)

---
title: NVD CPE-data completeness diagnostic
type: architecture
module: src/evaluation/nvd_completeness
tags: [architecture, module, nvd, diagnostic, cpe, completeness]
---

# NVD CPE-data completeness diagnostic

`src/evaluation/nvd_completeness/` holds the **deterministic core** of the NVD
completeness diagnostic described in [[prd-nvd-completeness-diagnostic]] (source
idea: [[nvd-completeness-diagnostic]]). Unlike the six [[tool-adapters|SCA
adapters]], NVD is **CPE-indexed, not PURL-indexed**, so it is delivered as a
side-by-side *diagnostic* — never a detection tool. It emits no `Finding`s into
the [[evaluation-core]] pipeline, never produces TP / FP<sub>GT</sub> / FN, and
never computes **Overlap** ([[decision-0008-heuristic-vs-ground-truth-separation]]).

See also: [[overview]], [[tool-adapters]], [[glossary]].

## The single seam

All paper-critical logic lives in one pure, I/O-free function,
`coverage.classify_nvd_coverage(gt_observation, parsed_nvd_record) -> bucket`.
It maps a [[glossary|ground-truth observation]] and the parsed NVD record for its
CVE (or `None` for "CVE absent") to exactly one **coverage bucket**, in
precedence order:

    NO_CVE → CVE_ABSENT → NO_CPE_CONFIG → PRODUCT_MISMATCH → PRODUCT_MATCHED

`PRODUCT_MATCHED` is the closest-to-covered bucket; the version split
(`COVERED` vs `VERSION_OUT_OF_RANGE`) and the headline completeness ratio are a
later slice. `PRODUCT_MISMATCH` ("wrong product") is kept strictly **distinct**
from any version gap — the matcher never consults versions.

## Modules

| Module | Responsibility |
|---|---|
| `record.py` | `NvdCpeNode` / `ParsedNvdRecord` typed view + `parse_nvd_record(raw)`: flattens an NVD 2.0 `configurations → nodes → cpeMatch` tree into vulnerable CPE nodes `(vendor, product, exact version, versionStart*/End* bounds)`. Returns `None` when the CVE is absent; never raises on a malformed body. |
| `coverage.py` | The `classify_nvd_coverage` seam, the **generous within-CVE product matcher** (`component_tokens`, `node_product_match`), the bucket constants, and the greppable per-observation log line (`NVD_COVERAGE | bucket=… `). |
| `report.py` | `aggregate_buckets` / `render_report`: per-ecosystem (pypi/npm/maven always shown) bucket counts + denominator + provisional product-matched ratio, with a run-metadata header stamping fetch date / NVD API version / ground-truth name (the point-in-time, non-reproducible qualifier). |

## Generous within-CVE product matching

Because OSV already asserts the CVE affects the component, a CPE node matches
when its product **or** vendor *contains* the normalized component token (exact
preferred over substring). Maven's `group:artifact` identity contributes **both**
segments as candidate tokens; tokens and CPE fields are compared after a
conservative canonicalization (lowercase, unify `_`/`-`). The `matched_nodes`
count in the per-observation log line is the spot-check guard for the
product-matcher-fidelity open question in the PRD.

## Not yet built here

The live `nvd` adapter (HTTP transport, `NVD_API_KEY` rate limiting, retry/backoff,
`*_api.log` tracing) and the runner entry point that drives these functions
against live NVD — plus the `core/tools.py` id registration and `.env`
documentation — are the walking-skeleton wiring tracked separately. Everything in
this package is pure and network-free, exercised by `tests/test_nvd_completeness.py`
over recorded NVD fixtures.

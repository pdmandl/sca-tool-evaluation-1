---
title: NVD CPE-data completeness diagnostic
type: architecture
module: src/evaluation/nvd_completeness + adapters/nvd.py
tags: [architecture, module, nvd, diagnostic, cpe, completeness]
---

# NVD CPE-data completeness diagnostic

`src/evaluation/nvd_completeness/` + `src/evaluation/adapters/nvd.py` implement
the NVD completeness diagnostic described in [[prd-nvd-completeness-diagnostic]]
(source idea: [[idea-nvd-completeness-diagnostic]]). Unlike the six
[[tool-adapters|SCA adapters]], NVD is **CPE-indexed, not PURL-indexed**, so it
is delivered as a side-by-side *diagnostic* — never a detection tool. It emits no
`Finding`s into the [[evaluation-core]] pipeline, never produces TP / FP<sub>GT</sub>
/ FN, and never computes **Overlap** ([[decision-0008-heuristic-vs-ground-truth-separation]]).

This note describes the current state: a complete end-to-end path from ground
truth to per-ecosystem coverage-bucket counts, with **generous within-CVE product
matching**. The remaining version-precise slice (does the observed version fall
inside a matched CPE range?) is layered on top of the same classifier seam — see
_Remaining slice_ below.

See also: [[overview]], [[tool-adapters]], [[orchestration-and-runners]], [[glossary]].

## End-to-end shape

1. **Runner** (`runner.py`, own entry point `python -m
   evaluation.nvd_completeness.runner --ground-truth <csv>`) reads the *same*
   ground-truth CSV every tool uses, seeds from the ground-truth CVEs,
   **de-duplicates** them, and issues **one NVD request per unique CVE**. It
   fails loudly on a missing / empty / malformed ground truth.
2. **Adapter** (`adapters/nvd.py`, `NvdAdapter`) is a `VulnerabilityToolAdapter`
   used purely for HTTP transport: it builds the NVD 2.0 REST query by `cveId`,
   honors `NVD_API_KEY` (50 req/30 s with a key, 5 anonymous — see the rate-limit
   pacing), backs off/retries on 429 & 5xx & transport errors, and traces every
   call through the base-class API log (`<gt>_nvd_api.log`). `fetch_record(cve)`
   returns a parsed record or `None` (CVE absent); it **raises** rather than
   silently reporting "absent" when transport fails after retries.
3. **Classifier seam** (`coverage.classify_nvd_coverage`) — the pure, I/O-free
   function `(gt_observation, parsed_nvd_record) -> bucket`. Buckets, in
   precedence order:
   `NO_CVE → CVE_ABSENT → NO_CPE_CONFIG → PRODUCT_MISMATCH → PRODUCT_MATCHED`.
   Product matching is *generous within a CVE* (OSV already asserts the CVE
   affects the component): a CPE node matches when its product **or** vendor
   contains the normalized component token (exact preferred over substring), with
   maven contributing both `group` and `artifact` as candidate tokens. The
   matcher never consults versions — "wrong product" stays distinct from a
   version gap.
4. **Report** (`report.py`) — per-ecosystem (pypi/npm/maven always shown) bucket
   counts and the denominator, plus a metadata header stamping UTC fetch date,
   NVD API version, and ground-truth name. Until the version slice lands the
   report publishes an interim **`product_matched_ratio`** (product-matched
   observations over the denominator) and deliberately **not** a "completeness"
   figure — `PRODUCT_MATCHED` counts matches regardless of version, so calling it
   completeness would over-report. Written to `<gt>_nvd_completeness.txt`; never
   into the standard evaluation report or the aggregated LaTeX tables.

## Modules

| Module | Responsibility |
|---|---|
| `adapters/nvd.py` | `NvdAdapter`: NVD 2.0 REST transport, `NVD_API_KEY` rate limiting, retry/backoff, `*_api.log` tracing, `fetch_record(cve) -> ParsedNvdRecord \| None`. No detection semantics (`load_findings_for_component` raises). |
| `record.py` | `NvdCpeNode` / `ParsedNvdRecord` typed view + `parse_nvd_record(raw)`: flattens an NVD 2.0 `configurations → nodes → cpeMatch` tree into vulnerable CPE nodes. Returns `None` when the CVE is absent; never raises on a malformed body. |
| `coverage.py` | The `classify_nvd_coverage` seam, the bucket constants, and the greppable per-observation log line (`NVD_COVERAGE | bucket=… `). |
| `report.py` | `aggregate_buckets` / `render_report` / `write_report`: per-ecosystem bucket counts + denominator + interim `product_matched_ratio`, with the point-in-time metadata header. |
| `runner.py` | The standalone entry point that wires the above against live NVD. |

## Denominator policy

`NO_CVE` observations (GHSA-only OSV entries) **stay in the denominator**:
"NVD is CVE-keyed and structurally can't cover GHSA-only entries" is part of the
completeness story. All three ecosystems are always shown, even at zero.

## Guardrails (structurally enforced)

- `nvd` is **not** in the `EVAL_TOOLS` default set, **not** in the `evaluate.py`
  `--tool` choices, and **not** run by `temporal_runner` — so Cochran-Q / McNemar
  significance and the aggregated tables are untouched.
- It **is** registered in the `_init_adapter` factory and in `core/tools.py`
  (`"NVD": "nvd"`) for filename/log consistency only, per
  [[decision-0001-adapter-pattern-for-tools]].
- **Overlap is never computed or printed** (a seed-from-GT-CVEs diagnostic
  structurally cannot emit FP<sub>GT</sub>, so Overlap would be a meaningless
  ≈1.0 artifact).

## Reproducibility caveat

NVD is queried **live**; it backfills CPE data and offers no historical query, so
the headline figure is **point-in-time, not reproducible** — an accepted
deviation from [[decision-0003-immutable-time-fixed-ground-truth]], labeled as
such in the report header.

## Remaining slice — version-precise coverage

The terminal `PRODUCT_MATCHED` bucket is split by the version-precise slice into
`COVERED` / `VERSION_OUT_OF_RANGE`, yielding the headline
`completeness = COVERED / denominator`. Over the **product-matched nodes only**,
an observation is `COVERED` iff its version falls inside at least one matched
node's applicability range (`versionStart*/End*` bounds, or an exact pinned CPE
version, or a bare wildcard = all versions); otherwise `VERSION_OUT_OF_RANGE`. An
unparseable range is never silently treated as covered, and ranges of unrelated
products in a multi-product CVE never flip the verdict. The parsed record already
carries the CPE nodes (`vendor`, `product`, exact version, `versionStart*/End*`
bounds) this slice needs; version comparison reuses
[[evaluation-core|`core/version_matching`]].

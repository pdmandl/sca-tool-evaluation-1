---
title: Ground-Truth Generation
type: architecture
module: src/ground_truth_generation
tags: [architecture, module, ground-truth, osv, sbom]
---

# Ground-Truth Generation

The `src/ground_truth_generation/` package builds the **gold-standard dataset**
that every evaluation is measured against. It collects vulnerable
package/version observations across four ecosystems, enriches them from OSV,
validates them, and emits a matched CSV + SBOM + statistics + metadata bundle.

See also: [[overview]], [[evaluation-core]], [[decision-0002-osv-as-single-source-of-truth]],
[[decision-0004-deterministic-balancing]].

## Entry point

`build_multi_ground_truth_dataset.py :: main()` (env-driven, no CLI flags).
Run with `python -m ground_truth_generation.build_multi_ground_truth_dataset`.

## Modules

| Module | Role |
|---|---|
| `build_multi_ground_truth_dataset.py` | Orchestrator: env parsing, per-ecosystem collection, canonicalization, capping, validation, balancing, artifact emission. |
| `ecosystems/pypi.py` | Collector for PyPI (curated ~100 packages). |
| `ecosystems/npm.py` | Collector for npm (curated ~100 packages, date-window filtered). |
| `ecosystems/maven.py` | Collector for Maven (~180 artifacts; date filter deliberately skipped — see [[decision-0006-maven-date-filter-disabled]]). |
| `ecosystems/nuget.py` | Collector for NuGet (~500 packages by category; even version sampling). |
| `osv_common.py` | Shared HTTP-with-retry, OSV advisory interpretation (`version_is_affected`, `expand_advisories`), `purl()`, date-window helpers. |
| `balancing.py` | Deterministic cross-ecosystem balancing + per-component capping. |
| `validation.py` | Per-ecosystem balance diagnostics (concentration, distribution). |
| `gt_statistics.py` | Human-readable `.stat.txt` report writer. |
| `api_call_tracker.py` | `ApiCallTracker`: per-API call counts + cumulative wall-clock. |

## Data flow

1. **Parse env** — `SAMPLES`, `ECOSYSTEMS`, `BALANCE`, `BALANCE_STRATEGY`,
   date window, capping vars. Validate against `{pypi, npm, maven, nuget}`.
2. **Collect per ecosystem** — each collector samples from a curated package
   list, fetches versions/release dates from the native registry (PyPI, npm
   registry, `maven-metadata.xml`, NuGet registration index), then POSTs each
   `(ecosystem, name, version)` to the OSV query API
   (`https://api.osv.dev/v1/query`). Responses cached in `osv_cache`.
3. **Enrich** — fetch a vulnerability description per OSV id
   (`OSV_VULN_URL`), cached; normalized to a single line ≤300 chars.
4. **Canonicalize** — dedupe on `(ecosystem, component_name, component_version, vulnerability_id)`.
5. **Cap** (optional) — keep newest N versions per component
   (`MAX_COMPONENT_VERSIONS_PER_COMPONENT`).
6. **Validate offline** — `verify_dataset_against_osv()` re-checks each row's
   vulnerability id against the cached OSV response; raises on mismatch.
7. **Balance** (optional) — see [[decision-0004-deterministic-balancing]].
8. **Emit artifacts** (all under `GROUND_TRUTH_BUILD_PATH`):
   - `{base}.csv` — the dataset
   - `{base}.stat.txt` — statistics
   - `{base}.sbom.json` — component-centric **CycloneDX 1.5** SBOM
   - `{base}.meta.json` — machine-readable metadata (schema version, window, per-ecosystem breakdown)

## Row schema

Each CSV row is one [[glossary#ground-truth-observation|ground-truth observation]]:

```
ecosystem, component_name, component_version, purl,
vulnerability_id, cve, vulnerability_description, is_vulnerable
```

`is_vulnerable` is always `true` in the generated set. The conceptual key is the
vulnerable tuple `(ecosystem, component, version, vulnerability_id)`.

## SBOM invariant

The SBOM contains **exactly** the components/versions present in the CSV (and
vice versa), so it can be handed to any SBOM-consuming scanner and to
Dependency-Track. Maven components are enriched with SHA-1/SHA-256 hashes when
available. See [[decision-0003-immutable-time-fixed-ground-truth]].

## Ecosystem-specific behaviour

- **PyPI** — no date filter; full release history queried.
- **npm** — versions filtered by publish date to `[START_DATE, END_DATE]`.
- **Maven** — date filter **disabled** for determinism ([[decision-0006-maven-date-filter-disabled]]); relies on OSV advisory dates.
- **NuGet** — date-filtered, then sampled *evenly* across surviving versions for temporal spread.

Per-ecosystem `*_MAX_VERSIONS_PER_PACKAGE` and `MAX_OSV_ENTRIES_PER_COMPONENT`
bound API load and data volume. `TARGET_VULNS_PER_ECOSYSTEM` +
`EARLY_STOP_ON_TARGET_VULNS` allow early termination without breaking
determinism (packages processed in fixed order).

## External dependencies

`requests`, `packaging`, `cyclonedx-python-lib` (SBOM build + strict JSON
validation), stdlib `csv`/`json`/`xml.etree`/`statistics`.

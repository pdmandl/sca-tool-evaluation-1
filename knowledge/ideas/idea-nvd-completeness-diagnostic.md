---
title: "NVD as a standalone CPE-data completeness diagnostic"
type: idea
status: proposed (grilled, spec signed off, not implemented)
tags: [idea, adapters, nvd, data-source, diagnostic, reproducibility]
---

# NVD as a standalone CPE-data completeness diagnostic

**Status:** Proposed — refined via a grilling session on 2026-07-02. No code
written yet.

## Sharpened problem

The starting wish was to add **Dependabot** as a new tool. Grilling reframed it:

- Dependabot's vulnerability data **is** the GitHub Advisory Database (GHSA),
  already queried by the existing `github` adapter — so it is redundant. It also
  has no SBOM/arbitrary-package API (only async scans of manifests in hosted
  repos), which fights the framework's
  [[decision-0003-immutable-time-fixed-ground-truth|time-fixed, reproducible]]
  design. **Rejected.**
- Surveying the existing adapters (OSV, GHSA, Snyk, OSS Index, and the
  aggregators Trivy / Dependency-Track), the one genuinely distinct free data
  source still missing is **NVD (NIST National Vulnerability Database)**. NVD is
  distinct in both data and paradigm: it is **CPE-indexed, not PURL/package-
  indexed** (see [[glossary]]).
- Because there is no reliable package→CPE mapping, NVD cannot be evaluated as a
  fair *detection* tool the way the
  [[decision-0005-identifier-gated-project-centric-matching|other tools]] are.
  The refined question it should answer instead:
  > *For vulnerabilities that exist per the GT/OSV, does NVD's CPE applicability
  > data correctly cover the affected version?*
  i.e. a measure of **NVD data completeness**, not detection.

## Decided approach

1. **Delivery** — a per-component API adapter `nvd`
   (`src/evaluation/adapters/nvd.py`), same contract as `github`/`osv`/
   `oss-index` ([[decision-0001-adapter-pattern-for-tools]]). Registered in
   `evaluate.py` `_init_adapter`, the `--tool` choices, `core/tools.py`
   (`"NVD": "nvd"`), and `.env` (`NVD_API_KEY`).
2. **Query strategy B — seed from GT CVEs.** For each GT row, query NVD live by
   `cveId` (deduped by CVE). Chosen over package→CPE "discovery" because the
   question is completeness, not detection.
3. **Coverage check B2 — version-precise.** "Covered" ⇔ the CVE's NVD config has
   an application CPE whose product/vendor matches the package **and** whose
   version range includes the GT version (`versionStart/End Including/Excluding`
   or exact CPE version).
4. **Product matching (b) — generous within-CVE token match.** Since OSV already
   asserts the CVE affects this package, match if the CPE product or vendor
   contains the normalized package token (exact preferred). Keeps
   product-mismatch and version-out-of-range as distinct outcome buckets.
5. **Miss taxonomy (the citable output):** (1) GT row has no CVE (GHSA-only OSV
   entry) → structural gap; (2) CVE absent/reserved/rejected in NVD; (3) CVE
   present but no CPE config; (4) CPE present but product mismatch; (5) product
   matched but version out of range.
6. **Framing — standalone diagnostic.** Report as "NVD CPE-data completeness"
   with a per-ecosystem breakdown (pypi / npm / maven). **Excluded** from the
   head-to-head table, default `EVAL_TOOLS`, and `temporal_runner` significance
   tests. **`Overlap` suppressed** — under strategy B it is a trivial ≈1.0
   artifact (querying only GT CVEs, the adapter structurally cannot produce
   FPs). Consistent with
   [[decision-0008-heuristic-vs-ground-truth-separation]].
7. **Reproducibility — live query (accepted tradeoff).** Consistent with the
   `github`/`oss-index` adapters. NVD backfills CPE data and offers no historical
   query, so the headline figure is **point-in-time, not reproducible**;
   mitigation is to stamp the fetch date + NVD API version into the report.
8. **Defaults:** no-CVE GT rows stay in the denominator (bucket 1); all three
   ecosystems are queried, since "gap by ecosystem" is the point. Rate limit:
   50 req/30s with an API key (5 anon).

## Open questions

- **Product-matcher fidelity.** How well does the generous within-CVE token match
  hold up in practice — especially Maven `groupId:artifactId` vs CPE
  `vendor:product`? If it is too strict it will over-report bucket 4 as "NVD
  gaps" that are really our matching failures.
- **Multi-product CVEs.** When a CVE lists several products with different version
  ranges, which node's range is authoritative for the version check?
- **Living with irreproducibility.** Is the point-in-time timestamp qualifier
  enough for how the number will be published, or does that pressure the earlier
  "cache-and-snapshot" option back onto the table?

## Related

- [[decision-0001-adapter-pattern-for-tools]]
- [[decision-0003-immutable-time-fixed-ground-truth]]
- [[decision-0005-identifier-gated-project-centric-matching]]
- [[decision-0008-heuristic-vs-ground-truth-separation]]
- [[tool-adapters]] · [[glossary]]

---
title: "PRD: NVD CPE-data completeness diagnostic"
type: prd
status: draft
source_idea: "[[idea-nvd-completeness-diagnostic]]"
tags: [prd, adapters, nvd, data-source, diagnostic, reproducibility]
---

# PRD: NVD CPE-data completeness diagnostic

Source idea: [[idea-nvd-completeness-diagnostic]] (refined via grilling, 2026-07-02).
Related decisions: [[decision-0001-adapter-pattern-for-tools]] ·
[[decision-0003-immutable-time-fixed-ground-truth]] ·
[[decision-0005-identifier-gated-project-centric-matching]] ·
[[decision-0008-heuristic-vs-ground-truth-separation]].

## Problem Statement

The framework compares SCA tools and advisory sources on **detection** against an
immutable, OSV-derived [[glossary|ground truth]] (Dependency-Track, Snyk, Trivy,
OSV, GitHub, OSS Index). A researcher extending the framework wants to add the
one genuinely distinct, still-missing free data source: **NVD** (NIST National
Vulnerability Database). NVD is unlike every existing source: it is
**CPE-indexed, not PURL/package-indexed**, and there is no reliable
package→CPE mapping.

That mismatch means NVD *cannot* be scored as a fair detection tool the way the
[[decision-0005-identifier-gated-project-centric-matching|other tools]] are —
running it through the standard TP / FP<sub>GT</sub> / FN pipeline would produce
misleading numbers. But NVD still carries information the paper cares about:
**does its CPE applicability data actually cover the vulnerable component
versions the ground truth already knows about?** Today there is no way to answer
that, so a reviewer cannot tell whether NVD's CPE data is complete enough to be
trusted as an authority for any given ecosystem.

The earlier framing ("add Dependabot as a tool") was rejected during grilling:
Dependabot's data *is* the GitHub Advisory Database already covered by the
`github` adapter, and it has no SBOM/arbitrary-package API, which fights the
[[decision-0003-immutable-time-fixed-ground-truth|time-fixed, reproducible]]
design.

## Solution

Add a **standalone NVD CPE-data completeness diagnostic**. Instead of asking "did
NVD detect this?", it asks:

> *For each vulnerability the ground truth already asserts (via its CVE), does
> NVD's CPE applicability data correctly cover the affected component version?*

The diagnostic seeds from ground-truth CVEs, queries NVD live by CVE id, and
classifies each ground-truth observation into a **miss taxonomy** of five
mutually exclusive coverage buckets. It reports a per-ecosystem
(pypi / npm / maven) **NVD CPE-data completeness** figure plus a breakdown of
*where* coverage is lost. It is deliberately kept out of the head-to-head
detection table so it can never be mistaken for a detection score.

From the researcher's point of view: run one new command against the same ground
truth, get a completeness report that says, e.g., "NVD covers 82% of pypi
ground-truth observations; 11% are lost to missing CPE configs, 5% to product
mismatch, 2% to version-out-of-range" — with the fetch date and NVD API version
stamped on it so the point-in-time nature is explicit.

## User Stories

1. As a framework researcher, I want to add NVD as a data source without it
   polluting the detection head-to-head table, so that NVD's non-comparable
   nature is structurally enforced rather than left to convention.
2. As a researcher, I want to run the NVD completeness diagnostic against the
   same ground-truth CSV I use for every other tool, so that the diagnostic is
   directly comparable in scope to the detection runs.
3. As a researcher, I want the diagnostic to seed from the CVEs already present
   in the ground truth, so that I measure completeness (not detection) and never
   depend on an unreliable package→CPE guess.
4. As a researcher, I want each ground-truth observation classified into exactly
   one of five coverage buckets, so that I can cite precisely *where* NVD's CPE
   data breaks down rather than just a single opaque percentage.
5. As a researcher, I want a per-ecosystem breakdown (pypi / npm / maven), so
   that I can report "NVD's CPE coverage is strong for npm but weak for maven"
   as a first-class finding.
6. As a researcher, I want ground-truth observations that have **no CVE**
   (GHSA-only OSV entries) counted as a distinct structural-gap bucket in the
   denominator, so that the completeness figure honestly reflects that NVD is
   CVE-keyed and cannot cover them at all.
7. As a researcher, I want a CVE that is absent / reserved / rejected in NVD
   distinguished from a CVE that is present but carries no CPE configuration, so
   that "NVD doesn't know this CVE" and "NVD knows it but never enumerated
   affected products" are not conflated.
8. As a researcher, I want a CVE whose CPE config exists but whose product/vendor
   does not match the component distinguished from one where the product matches
   but the version falls outside every applicability range, so that matching
   failures and genuine version gaps stay separate.
9. As a researcher, I want product matching to be **generous within a CVE** —
   because OSV already asserts the CVE affects this component, a CPE whose
   product or vendor contains the normalized component token counts as a match —
   so that I do not over-report our own matching weakness as an "NVD gap."
10. As a researcher, I want the version check to be **version-precise** —
    honoring `versionStartIncluding` / `versionEndExcluding` (and their
    variants) and exact CPE versions — so that "covered" genuinely means NVD's
    applicability range includes the ground-truth version.
11. As a researcher evaluating a CVE that lists several products with different
    ranges, I want "covered" decided over the product-matched nodes, so that
    ranges for unrelated products in the same CVE don't distort the verdict.
12. As a researcher, I want **Overlap suppressed** for this diagnostic, so that a
    trivially ≈1.0 artifact (the diagnostic structurally cannot emit
    FP<sub>GT</sub>, since it only queries GT CVEs) is not printed as if it were a
    precision result.
13. As a researcher, I want the diagnostic excluded from the default
    `EVAL_TOOLS` set and from the `temporal_runner` significance tests, so that
    adding it never changes existing Cochran-Q / McNemar results.
14. As a researcher, I want the fetch date and the NVD API version stamped into
    the report, so that the point-in-time, non-reproducible nature of the
    headline number is explicit wherever it is published.
15. As a researcher, I want the NVD query to use an API key when
    `NVD_API_KEY` is present (raising the rate limit from 5 to 50 requests per
    30 s) and to fall back to anonymous access otherwise, so that runs are
    faster when a key is configured but still work without one.
16. As a researcher, I want CVEs de-duplicated before querying NVD, so that a CVE
    appearing on multiple ground-truth observations is fetched only once.
17. As a researcher, I want the diagnostic to reuse the shared adapter API-call
    tracing (per-tool `*_api.log`), so that NVD requests are auditable exactly
    like every other source.
18. As a researcher, I want a clear, greppable per-observation log line stating
    the assigned bucket, so that I can spot-check the classification against the
    raw NVD response.
19. As a researcher, I want the NVD product-matcher and version-range logic
    exercised by unit tests over recorded NVD responses, so that the
    paper-critical classification is verified without hitting the network.
20. As a maintainer, I want NVD registered in the same touchpoints as every other
    adapter (factory, tool-id registry, `.env` documentation) where those
    touchpoints still make sense for a diagnostic, so that the code stays
    consistent with [[decision-0001-adapter-pattern-for-tools]].
21. As a maintainer, I want the diagnostic to fail loudly if the ground truth is
    empty or malformed, matching the existing adapters' behavior, so that silent
    zero-coverage reports can't happen.
22. As a reviewer reading the report, I want each ecosystem's completeness figure
    accompanied by its bucket counts and the denominator, so that I can
    reconstruct the percentage and audit it.

## Implementation Decisions

**Delivery shape — standalone diagnostic, not a detection tool.** NVD is
delivered as a diagnostic with its **own entry point** (a new
`nvd_completeness` runner module under `src/evaluation/`), *not* as a `--tool`
choice flowing through `run_evaluation` / `evaluate_project_centric`. This
resolves the tension in the source idea (which called it "an adapter, same
contract" while also requiring exclusion from the TP/FP/FN machinery): the NVD
adapter reuses `VulnerabilityToolAdapter` purely for HTTP transport, API-call
tracing, and progress iteration, but coverage classification never enters the
detection pipeline. *(Chosen by best judgment while the requester was away;
revisit if the requester prefers the full-`run_evaluation` route.)*

- **The single seam.** All paper-critical, deterministic logic lives in **one
  pure function**, `classify_nvd_coverage(gt_observation, parsed_nvd_record) ->
  CoverageBucket`. It takes a ground-truth observation and the parsed NVD record
  for that observation's CVE (or a sentinel for "CVE absent from NVD") and
  returns exactly one bucket. It performs no I/O. This is the highest, and
  ideally the only, seam at which the diagnostic is tested.
- **NVD adapter (`nvd`).** A `VulnerabilityToolAdapter` subclass
  (`src/evaluation/adapters/nvd.py`) responsible only for: building the NVD
  REST query by `cveId`, honoring the API key / rate limit, tracing calls via the
  base class `_api_call`, and returning the *parsed* NVD record (raw JSON →
  a small typed view of CPE configuration nodes). It does **not** emit `Finding`s
  into the evaluation core and does **not** implement detection semantics.
- **Query strategy — seed from ground-truth CVEs (idea's "strategy B").** For
  each ground-truth observation, take its `cve` field, de-duplicate across
  observations, and query NVD live once per unique CVE. Chosen over
  package→CPE "discovery" because the question is completeness, not detection.
- **Coverage check — version-precise (idea's "B2").** A ground-truth observation
  is *covered* iff, among the CVE's NVD CPE application nodes whose product/vendor
  matches the component, at least one node's applicability range includes the
  observation's version. Range inclusion honors
  `versionStartIncluding` / `versionStartExcluding` /
  `versionEndIncluding` / `versionEndExcluding` and exact CPE versions. Version
  comparison follows the framework's existing version-matching conventions; reuse
  the existing range machinery where the CPE range shape allows, and treat an
  unparseable range as *not covered* (never silently "covered").
- **Product matching — generous within-CVE token match (idea's "(b)").** Because
  OSV already asserts the CVE affects this component, a CPE node matches when its
  product or vendor contains the normalized component token (exact preferred over
  substring). For maven, the component is `group:artifact`; both segments are
  candidate tokens against CPE `vendor:product`. Product-mismatch and
  version-out-of-range remain **distinct** buckets — the matcher never collapses
  them.
- **Multi-product CVEs.** When a CVE lists several products with different
  ranges, "covered" is decided over the **product-matched nodes only**: covered
  if *any* product-matched node's range includes the version. Nodes for unrelated
  products in the same CVE are ignored (not counted as version-out-of-range).
  *(Chosen by best judgment; this is the "generous within-CVE" reading. Revisit
  if a stricter all-matched-nodes-must-agree rule is preferred.)*
- **Miss taxonomy — five mutually exclusive buckets** (the citable output),
  evaluated in precedence order per ground-truth observation:
  1. `NO_CVE` — the observation has no CVE (GHSA-only OSV entry) → structural gap
     NVD cannot cover by construction.
  2. `CVE_ABSENT` — CVE absent / reserved / rejected in NVD.
  3. `NO_CPE_CONFIG` — CVE present in NVD but carries no CPE configuration.
  4. `PRODUCT_MISMATCH` — CPE config present but no node's product/vendor matches
     the component.
  5. `VERSION_OUT_OF_RANGE` — product matched but the version falls outside every
     matched node's range.
  A sixth outcome, `COVERED`, is the success case (product matched **and** version
  in range). Completeness for an ecosystem = `COVERED / total observations in
  that ecosystem`.
- **Denominator policy.** `NO_CVE` observations **stay in the denominator**
  (bucket 1), because "NVD is CVE-keyed and structurally can't cover GHSA-only
  entries" is part of the completeness story. All three ecosystems (pypi / npm /
  maven) are always queried; "gap by ecosystem" is the point.
- **Overlap suppressed.** The diagnostic never computes or prints Overlap; under
  the seed-from-GT-CVEs strategy it structurally cannot produce FP<sub>GT</sub>,
  so Overlap would be a meaningless ≈1.0 artifact. Consistent with
  [[decision-0008-heuristic-vs-ground-truth-separation]] (do not print a number
  that isn't a real verdict).
- **Exclusion from head-to-head machinery.** `nvd` is **not** added to the
  default `EVAL_TOOLS` string and is **not** run by `temporal_runner`, so Cochran-Q
  / McNemar significance and the aggregated comparison table are untouched.
- **Registration touchpoints.** Register the adapter in the `_init_adapter`
  factory and add a stable tool id (`"NVD": "nvd"`) to `core/tools.py` for
  filename/log consistency, per [[decision-0001-adapter-pattern-for-tools]].
  Document `NVD_API_KEY` in `.env(.example)`. The `--tool` CLI **choices** of
  `evaluate.py` should *not* gain `nvd` (it is not a detection tool); the
  diagnostic is invoked through its own runner entry point instead.
- **Reproducibility — live query, accepted tradeoff.** Consistent with the
  `github` / `oss-index` adapters, NVD is queried live. NVD backfills CPE data and
  offers no historical query, so the headline figure is **point-in-time, not
  reproducible**. Mitigation: stamp the UTC fetch date and the NVD API version
  into the report header. This is an accepted deviation from
  [[decision-0003-immutable-time-fixed-ground-truth]] and must be labeled as such
  in the output.
- **Rate limiting.** Honor NVD's documented limits: 50 requests / 30 s with a key,
  5 / 30 s anonymous. Read the key from `NVD_API_KEY`; back off and retry on 429
  / transport errors, mirroring the retry/backoff style already used by the
  `oss-index` adapter.
- **Report contract.** The diagnostic writes a dedicated
  `*_nvd_completeness` report artifact containing, per ecosystem: the six bucket
  counts, the denominator, the derived completeness ratio, and the run metadata
  header (fetch date, NVD API version, ground-truth name). It does **not** write
  into the standard evaluation report or the aggregated LaTeX tables.

## Testing Decisions

**What makes a good test here:** exercise externally observable behavior — the
coverage verdict — not internal helpers. The classifier's contract is
`(ground-truth observation, parsed NVD record) → bucket`; tests should assert the
bucket, driving inputs from **recorded NVD responses** rather than the live API.

- **Primary target — the single seam.** `classify_nvd_coverage` gets the bulk of
  the tests: one focused case per bucket, using small fixture NVD records
  (`COVERED`, `NO_CVE`, `CVE_ABSENT`, `NO_CPE_CONFIG`, `PRODUCT_MISMATCH`,
  `VERSION_OUT_OF_RANGE`), plus edge cases: generous vendor-vs-product token
  match, maven `group:artifact` tokenization, `versionStart*/End*` boundary
  inclusivity (inclusive vs exclusive at both ends), exact-CPE-version match, an
  unparseable range (→ not covered), and a multi-product CVE where one
  non-matching product's range would spuriously "cover" the version if the
  product filter were skipped.
- **Secondary target — NVD record parsing.** Given a recorded raw NVD JSON body,
  the adapter's parse step yields the expected typed CPE nodes (product, vendor,
  range bounds, inclusivity flags). Also cover the CVE-absent / reserved / rejected
  response shapes so the runner maps them to `CVE_ABSENT` / `NO_CPE_CONFIG`
  correctly.
- **Runner-level (thin).** A small test that, with the adapter's network call
  mocked/patched, the runner de-duplicates CVEs, keeps `NO_CVE` observations in
  the denominator, aggregates buckets per ecosystem, and never emits Overlap.
- **Prior art to follow.** Mirror `tests/test_oss_index.py` and
  `tests/test_adapters.py` (construct the adapter with a `GROUND_TRUTH_BUILD_PATH`
  tmp dir and a stubbed env; patch the HTTP layer with `unittest.mock`). Follow
  `tests/test_version_matching.py` for range-boundary style tests. The suite must
  not hit the network.

## Out of Scope

- **NVD as a detection tool / part of the head-to-head table.** No TP / FP<sub>GT</sub>
  / FN, Recall, or significance participation for NVD.
- **Package→CPE discovery / mapping.** We deliberately do *not* attempt to find
  NVD entries from a package identifier; we only seed from ground-truth CVEs.
- **Reproducible / snapshotted NVD data.** Caching or historical snapshotting of
  NVD responses to make the figure reproducible is explicitly out of scope for
  this PRD (see open question below); the accepted approach is live query +
  timestamp qualifier.
- **New ecosystems.** Only the existing pypi / npm / maven ground truth is
  covered; nuget and others are not added here.
- **Changes to the existing detection pipeline, `evaluate_project_centric`,
  `temporal_runner`, or the aggregated LaTeX/plots.** The diagnostic is additive
  and side-by-side.
- **Dependabot.** Rejected in the source idea as redundant with GHSA; not
  revisited.

## Further Notes

Open questions carried over from [[idea-nvd-completeness-diagnostic]] to watch
during implementation and review:

- **Product-matcher fidelity.** How well the generous within-CVE token match
  holds up in practice, especially maven `groupId:artifactId` vs CPE
  `vendor:product`. If too strict, it over-reports `PRODUCT_MISMATCH` as "NVD
  gaps" that are really our matching failures. The per-observation bucket log line
  exists precisely to spot-check this.
- **Living with irreproducibility.** Whether the point-in-time timestamp qualifier
  is enough for how the number will be published, or whether it pressures the
  "cache-and-snapshot" option back onto the table. Deferred; not blocking.
- **Multi-product authoritative node.** The "any product-matched node" rule was
  chosen by best judgment; confirm with the requester before publishing figures.

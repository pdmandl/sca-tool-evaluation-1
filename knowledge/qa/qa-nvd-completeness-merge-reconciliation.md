---
title: "QA plan: NVD completeness diagnostic — merge reconciliation + version-precise slice"
type: qa
status: draft
date: 2026-07-02
scope: src/evaluation/nvd_completeness + src/evaluation/adapters/nvd.py
targets:
  - "#1 NVD walking-skeleton runner + adapter (1571d48)"
  - "#2 NVD coverage classifier buckets + generous product matcher (92f5566)"
  - "merge d047b7b"
tags: [qa, test-plan, nvd, diagnostic, cpe, completeness, merge-conflict]
---

# QA plan: NVD completeness diagnostic

Covers the NVD CPE-data completeness diagnostic
([[nvd-completeness-diagnostic]], [[prd-nvd-completeness-diagnostic]]) as it
landed on `main` via the out-of-order merge of issues **#1** (walking skeleton,
coarse 3-bucket) and **#2** (precision, 5-bucket) — see
[[idea-nvd-completeness-diagnostic]]. The two branches overlapped on the same
files and the merge (`d047b7b`) left `main` in a **broken, non-importable
state**. This plan defines the reconciliation work and the tests that prove it,
then the remaining PRD slice (version-precise coverage).

See also: [[evaluation-core]], [[tool-adapters]], [[orchestration-and-runners]],
[[decision-0008-heuristic-vs-ground-truth-separation]], [[glossary]].

## Verified current state of `main` (as of 2026-07-02)

The merge combined **#2's** `coverage.py` / `record.py` / `report.py` (5-bucket
vocabulary) with **#1's** `runner.py` and `tests/test_nvd_completeness.py`
(3-bucket vocabulary), plus a `report.py` that references a *third* name that
exists in neither branch. Concretely:

| # | Location | Symbol referenced | Defined in `coverage.py`? | Effect |
|---|---|---|---|---|
| B1 | `report.py:21`, `:44` | `COVERED_BUCKET` | **No** (only `PRODUCT_MATCHED`) | `ImportError` → `report.py`, `runner.py`, and both test modules fail at import |
| B2 | `tests/test_nvd_completeness.py:21` | `PRESENT` | **No** (only `NO_CPE_CONFIG` / `PRODUCT_MISMATCH` / `PRODUCT_MATCHED`) | Test module cannot be collected — entire NVD suite errors |
| B3 | `tests/test_smoke_imports.py:41` | imports `nvd_completeness.report` | — | Transitively hits B1 → smoke test fails |

Net: **the diagnostic cannot be imported or run, and 100% of its tests error at
collection.** Both PRs are marked merged/closed, so this is a silent regression
masked by the merge.

Secondary inconsistencies (non-crashing, but wrong):
- **Semantic drift in the completeness ratio.** `report.completeness()` divides
  `PRODUCT_MATCHED / denominator`. Per the [[prd-nvd-completeness-diagnostic|PRD]]
  the headline number is `COVERED / denominator`, where `COVERED` requires the
  version to fall inside a matched CPE range. `PRODUCT_MATCHED` counts
  product-matched-regardless-of-version, so the current figure **over-reports
  completeness**. This must not be published.
- **Self-contradicting docstring.** `report.py:10-12` still describes the coarse
  `PRESENT / total` skeleton while the code imports `COVERED_BUCKET`.
- **Architecture note is concatenated across both PRs.** The top of
  [[nvd-completeness-diagnostic]] documents the 3-bucket `NO_CVE → CVE_ABSENT →
  PRESENT` skeleton; the appended "Later slices" section documents the 5/6-bucket
  taxonomy. Reads as two half-truths.
- **Undocumented env knobs.** The adapter reads `NVD_MAX_RETRIES`,
  `NVD_RETRY_BACKOFF_S`, `NVD_MIN_REQUEST_INTERVAL_S`; only `NVD_API_KEY` is in
  `.env_example`.

## Risk areas

1. **Bucket-vocabulary reconciliation (highest).** One canonical vocabulary must
   win across `coverage.py`, `report.py`, `runner.py`, the test file, and the
   architecture note. Recommended canonical = **#2's precision taxonomy**, since
   its matcher/parser are the more complete code and the PRD's final taxonomy is
   built on it.
2. **Completeness-ratio correctness.** Whatever bucket the denominator's
   numerator uses must be the *true* covered bucket, or the published figure is
   wrong. Until the version slice lands, the report must not label
   `PRODUCT_MATCHED` as "completeness".
3. **Guardrail integrity ([[decision-0008-heuristic-vs-ground-truth-separation]]).**
   NVD must stay out of `EVAL_TOOLS`, out of `evaluate.py --tool` choices, and
   out of `temporal_runner`; Overlap must never be computed/printed. A merge that
   re-touched `evaluate.py` / `core/tools.py` could have regressed this.
4. **Denominator policy.** `NO_CVE` observations must remain in the denominator
   (structural-gap story). A vocabulary rewrite risks silently dropping them.
5. **Adapter transport robustness.** Rate-limit pacing (5 vs 50 req/30 s),
   429/5xx/transport retry+backoff, `Retry-After` honoring, 404/empty-list →
   `None` (absent) vs raise-on-exhausted-retries. Regressions here either hammer
   NVD (ban risk) or silently miscount transport failures as "CVE absent".
6. **`parse_nvd_record` shape coverage.** Full NVD-2.0 envelope vs unwrapped CVE
   object; nested `nodes`/`children` AND/OR trees; `vulnerable:false` node
   filtering; `*`/`-` version → `None`; malformed body must never raise.
7. **Point-in-time reproducibility labelling.** The report header must stamp UTC
   fetch date + NVD API version and carry the not-reproducible caveat
   ([[decision-0003-immutable-time-fixed-ground-truth]] deviation).
8. **Runner failure-loudness.** Missing / empty / malformed ground truth must
   `SystemExit`, never emit a silent zero-coverage report.

## Implementation plan

### Priority 1 — Reconcile the broken merge (blocking; do first)

P1 makes `main` import, run, and pass its own suite again. No new behaviour.

1. **Pick the canonical vocabulary = #2's 5 buckets**: `NO_CVE`, `CVE_ABSENT`,
   `NO_CPE_CONFIG`, `PRODUCT_MISMATCH`, `PRODUCT_MATCHED`, precedence
   `NO_CVE → CVE_ABSENT → NO_CPE_CONFIG → PRODUCT_MISMATCH → PRODUCT_MATCHED`.
2. **Fix `report.py` (B1).** Replace the `COVERED_BUCKET` import/usage. Until the
   version slice exists, either (a) compute an explicit *interim* "product-matched
   ratio" clearly labelled as **not** final completeness, or (b) introduce
   `COVERED_BUCKET = PRODUCT_MATCHED` as a single documented alias and label the
   ratio honestly. Prefer (a): rename the field to `product_matched_ratio` and
   omit a "completeness" figure until P2 lands, so nobody cites an over-count.
   Update the docstring to match.
3. **Rewrite `tests/test_nvd_completeness.py` (B2)** to the canonical vocabulary:
   replace `PRESENT` imports/assertions with the 5 buckets; split the old
   `test_present*` cases into `test_no_cpe_config`, `test_product_mismatch`,
   `test_product_matched`. Keep the runner/adapter/parse tests.
4. **Confirm the smoke import (B3)** passes once B1 is fixed.
5. **Reconcile the architecture note** [[nvd-completeness-diagnostic]] into one
   coherent description of the 5-bucket state + the planned version slice; drop
   the stale 3-bucket skeleton prose.
6. **Document the adapter env knobs** (`NVD_MAX_RETRIES`, `NVD_RETRY_BACKOFF_S`,
   `NVD_MIN_REQUEST_INTERVAL_S`) in `.env_example`.
7. **Re-verify guardrails**: `grep` that `nvd` is absent from `EVAL_TOOLS`, the
   `evaluate.py --tool` choices, and `temporal_runner`; that `NvdAdapter.
   load_findings_for_component` still raises; that no Overlap path exists.

### Priority 2 — Complete the version-precise slice (the real headline)

Implements PRD user-stories 8, 10, 11 and yields the citable
`COVERED / denominator` figure.

1. Split `PRODUCT_MATCHED` into terminal buckets **`COVERED`** and
   **`VERSION_OUT_OF_RANGE`** — precedence becomes
   `NO_CVE → CVE_ABSENT → NO_CPE_CONFIG → PRODUCT_MISMATCH → VERSION_OUT_OF_RANGE
   → COVERED`.
2. In `classify_nvd_coverage`, over the **product-matched nodes only**, mark
   `COVERED` iff at least one matched node's applicability range includes the
   observation's version; honor `versionStartIncluding/Excluding` +
   `versionEndIncluding/Excluding` and exact CPE versions. Multi-product CVEs:
   ranges of *unrelated* products must be ignored (PRD story 11).
3. Reuse the framework's existing version-matching machinery
   ([[decision-0005-identifier-gated-project-centric-matching]] / the version
   comparators) where the CPE range shape allows; an **unparseable range → not
   covered**, never silently covered.
4. Restore `completeness() = COVERED / denominator` in `report.py`; render all
   six bucket counts + denominator + ratio.

## Test scenarios

### A. Classifier seam — `classify_nvd_coverage` (primary target, pure/no-network)

Happy path (one focused case per bucket, from small fixture records):
- `NO_CVE` — observation has empty/blank `cve` field.
- `CVE_ABSENT` — record is `None` (NVD 200 + empty `vulnerabilities`, or 404).
- `NO_CPE_CONFIG` — record present, `cpe_nodes == []`.
- `PRODUCT_MISMATCH` — CPE nodes present, none match the component token.
- `PRODUCT_MATCHED` (P1) / `COVERED` (P2) — product matches and (P2) version in range.
- `VERSION_OUT_OF_RANGE` (P2) — product matches, version outside every matched range.

Edge cases:
- **Precedence:** `NO_CVE` wins even when a record is somehow supplied
  (keep `test_no_cve_takes_precedence_over_record`).
- **Generous matching:** match on **vendor** token when product doesn't match,
  and vice-versa; **exact preferred over substring**.
- **Maven tokenization:** `group:artifact` contributes *both* segments as
  candidate tokens against CPE `vendor:product`.
- **Token canonicalization:** case/punctuation-normalized match
  (`_canon`) — e.g. `Spring-Framework` vs `spring_framework`.
- **(P2) Boundary inclusivity:** at each of `versionStartIncluding` /
  `Excluding` / `versionEndIncluding` / `Excluding`, assert covered vs not
  exactly at the boundary version.
- **(P2) Exact CPE version:** node pins a single version (URI field 5 not `*`/`-`).
- **(P2) Unparseable range → not covered** (never silently `COVERED`).
- **(P2) Multi-product CVE:** an unrelated product whose range *would* include
  the version must **not** flip the verdict to `COVERED`.
- **Greppable log line:** `format_coverage_log_line` starts with
  `NVD_COVERAGE | bucket=<BUCKET>` for the canonical bucket names.

### B. Record parser — `parse_nvd_record` (pure/no-network)

- Full NVD-2.0 envelope `{"vulnerabilities":[{"cve":{...}}]}` → nodes extracted.
- Already-unwrapped CVE object `{"id":..., "configurations":[...]}` → nodes.
- Absent CVE (empty/missing `vulnerabilities`) → `None`.
- **Malformed body never raises** → `None` or empty nodes (assert no exception).
- `vulnerable:false` nodes dropped.
- Nested `nodes`/`children` AND/OR tree flattened.
- `*` / `-` / empty version field → `version is None`; real version preserved.
- Range qualifiers carried verbatim onto `NvdCpeNode`.

### C. Report aggregation — `aggregate_buckets` / `render_report` / `write_report`

- `pypi`, `npm`, `maven` **always present** even at zero.
- Every canonical bucket key present per ecosystem (stable layout).
- `NO_CVE` **counted in the denominator** (`test_no_cve_stays_in_denominator`).
- Extra ecosystem in data (e.g. `nuget`) appears in addition to the defaults.
- Ratio math reconstructs from counts/denominator; denominator 0 → 0.0 (no
  ZeroDivision).
- Header carries `ground_truth`, `fetch_date_utc`, `nvd_api_version`, and the
  not-reproducible NOTE; **no "Overlap" string anywhere** in the rendered text.
- `write_report` writes `<gt>_nvd_completeness.txt` to the GT's directory and
  returns the path.

### D. Adapter transport — `NvdAdapter` (network mocked with `unittest.mock`)

- Rate interval depends on key: `min_interval_s` = 30/50 with key vs 30/5
  anonymous; `apiKey` header set only when key present.
- `fetch_record` present → parsed record; absent (empty list) → `None`;
  HTTP 404 → `None`.
- Empty/blank `cve_id` short-circuits to `None` (no HTTP call).
- **429 then 200** retries and succeeds; **5xx then 200** retries; transport
  exception then 200 retries; `Retry-After` header honored (capped).
- **Exhausted retries raise `RuntimeError`** — never silently returns `None`
  (a transport failure must not masquerade as `CVE_ABSENT`).
- Every call traced through the base-class `*_api.log`.
- `load_findings_for_component` raises `NotImplementedError` (no detection).
- `_capture_api_version` fills `api_version` from the first successful body.

### E. Runner — `run_nvd_completeness` (adapter injected/faked; no network)

- `_unique_cves` de-dupes and preserves order; blank CVEs skipped.
- **One request per unique CVE** (assert fake adapter call count == unique count).
- Missing / empty / malformed (no ecosystem column) GT → `SystemExit`.
- Per-ecosystem counts correct end-to-end; report artifact written.
- Never computes/prints Overlap; NVD never enters the detection report.

## Regression checks

- `pytest tests/test_nvd_completeness.py tests/test_smoke_imports.py` — full
  green (currently: collection error).
- `pytest tests/test_tools.py` — NVD registered as a tool id (`"NVD":"nvd"`)
  without appearing in `EVAL_TOOLS`.
- Full `pytest` run: no drop from the repo's ~90% coverage baseline (commit
  `1ab9a98`); no new import errors elsewhere.
- `evaluate.py --help` still lists the **same `--tool` choices** (no `nvd`).
- `temporal_runner` significance path unchanged — Cochran-Q / McNemar results
  byte-identical on a fixed GT before/after.
- `grep -rn "Overlap" src/evaluation/nvd_completeness` → no matches.

## Manual verification steps

1. **Import smoke (was failing):**
   `python -c "import sys; sys.path.insert(0,'src'); import evaluation.nvd_completeness.report, evaluation.nvd_completeness.runner"`
   → no `ImportError`.
2. **Offline runner demo:** run `run_nvd_completeness` with a small fixture GT
   CSV and a faked adapter; confirm the printed report shows all three
   ecosystems, sane bucket counts, the metadata header, the not-reproducible
   NOTE, and **no Overlap line**.
3. **Live smoke (rate-limited, small GT ≤10 CVEs):** with and without
   `NVD_API_KEY`, run against a tiny real GT; confirm `*_nvd_api.log` traces one
   line per unique CVE, pacing differs with the key, and the run completes.
4. **Spot-check the matcher fidelity (PRD open question):** pick 3–5
   `NVD_COVERAGE | bucket=PRODUCT_MISMATCH` log lines and manually diff the
   normalized component token against the CVE's CPE `vendor:product` in the raw
   NVD response — confirm they are genuine NVD gaps, not our matcher being too
   strict (especially maven `groupId:artifactId`).
5. **Artifact isolation:** confirm the standard evaluation report and the
   aggregated LaTeX tables/plots are byte-unchanged by an NVD run.

## Acceptance criteria

- [ ] `evaluation.nvd_completeness.{coverage,record,report,runner}` and
      `adapters.nvd` all import with **no `ImportError`** (B1–B3 fixed).
- [ ] A single canonical bucket vocabulary is used consistently across code,
      tests, and the architecture note; no `PRESENT`/`COVERED_BUCKET` dangling
      references remain.
- [ ] `tests/test_nvd_completeness.py` and `tests/test_smoke_imports.py` pass;
      full `pytest` is green with coverage ≥ the current baseline.
- [ ] The report never presents `PRODUCT_MATCHED` as "completeness"; the headline
      `completeness = COVERED / denominator` appears **only** after the P2
      version slice lands (interim reports label the product-matched ratio
      honestly).
- [ ] Guardrails intact: `nvd` absent from `EVAL_TOOLS`, `--tool` choices, and
      `temporal_runner`; Overlap never computed/printed; `load_findings_for_component`
      raises.
- [ ] `NO_CVE` observations remain in the denominator; all three ecosystems
      always shown.
- [ ] Report header stamps UTC fetch date + NVD API version + not-reproducible
      caveat.
- [ ] Adapter: correct rate pacing by key, retry/backoff on 429/5xx/transport,
      `Retry-After` honored, exhausted retries **raise** (not silent-absent),
      404/empty → `None`, calls traced.
- [ ] (P2) Version-range inclusivity, exact-version, unparseable-range→not-covered,
      and multi-product product-scoping all verified by unit tests over recorded
      fixtures; the suite hits **no network**.
- [ ] `.env_example` documents all adapter-read `NVD_*` env vars.

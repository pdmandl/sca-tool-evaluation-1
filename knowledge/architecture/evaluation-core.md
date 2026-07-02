---
title: Evaluation Core
type: architecture
module: src/evaluation/core
tags: [architecture, module, evaluation, matching, metrics]
---

# Evaluation Core

`src/evaluation/core/` holds the **matching and classification engine** — the
layer that *decides* TP / FP<sub>GT</sub> / FN. Everything downstream
([[analysis-and-significance]], [[reporting]]) only consumes its output.

See also: [[overview]], [[tool-adapters]], [[glossary]],
[[decision-0005-identifier-gated-project-centric-matching]].

## The Finding model (`model.py`)

A single dataclass `Finding` represents **both** ground-truth entries and tool
findings:

- Identity: `ecosystem`, `component`, `version`
- Identifiers: `cve`, `ghsa`, `osv_id` (+ `purl`); `identifiers()` returns the
  set of present ids
- Metadata: `description`, `source`, `cve_cpes`
- Range: `affected_version_range`
- Result fields (filled by evaluation): `match_type` (`TP_EXACT`/`TP_RANGE`),
  `fp_class`, `fp_reason`, `fp_score`, `fp_rules`

## Normalization (`normalization.py`)

Applied **symmetrically** to ground truth and tool findings before any
comparison. No fuzzy matching anywhere.

- `normalize_component(ecosystem, name)` — PyPI → PEP 503 canonical
  (lowercase, `_`→`-`); npm → lowercase; Maven → preserve `group:artifact`;
  NuGet → preserve case.
- `normalize_identifier()` — uppercase `CVE-`/`GHSA-`; OSV ids as-is.
- `normalize_version()` — trim only (no semver coercion).
- `ecosystem_from_purl()` — extract ecosystem from a Package URL.

## Ecosystems & tools registries

- `ecosystems.py` — frozen `EcosystemMapping(canonical, purl, osv, github)` per
  ecosystem, e.g. pypi→(pypi, pypi, PyPI, PIP). Bridges the naming differences
  between OSV, GitHub, and PURL.
- `tools.py` — `TOOL_FILE_IDS` maps display names to filesystem-safe ids used in
  artifact filenames.

## Matching (`evaluation.py` + `version_matching.py`)

`evaluate_project_centric(ground_truth, tool_findings)` is **project-centric**:
a project state is a fixed set of `(ecosystem, component, version)` tuples.
For each ground-truth entry it looks at tool findings for the *same component*
and applies a cascade:

1. **Identifier gate** — require `gt.identifiers() ∩ finding.identifiers() ≠ ∅`.
   Without an id overlap the finding can never be a match.
2. **`TP_EXACT`** — tool version == GT version.
3. **`TP_RANGE`** — tool reports a range and GT version ∈ range
   (`version_in_range()` handles Maven `[1.0,2.0)`, hyphen, and PEP440 forms;
   returns `False` on invalid versions/specifiers).
4. Otherwise the GT entry becomes an **FN**.

Any tool finding never matched → **FP** (FP<sub>GT</sub>). Returns
`(tp_exact, tp_range, fp, fn)` — the **single source of truth**; all metrics
derive from these lists.

## FN classification (`evaluation.py :: classify_false_negatives`)

Strict precedence `FN_exact → FN_range → FN_true`:
- **FN_exact** — tool reported same `(component, version)` but non-matching ids.
- **FN_range** — GT version falls in a reported range but wasn't decisively matched.
- **FN_true** — tool reported nothing relevant.

## FP classification (`fp_classification.py`)

Diagnostic labels for FP<sub>GT</sub> findings (separate from ground truth —
see [[decision-0008-heuristic-vs-ground-truth-separation]]):
- **FP-CERTAIN** — CVE is not an alias of any OSV advisory for that component
  (live OSV alias check).
- **FP-LIKELY** — description mentions a foreign product ("server",
  "enterprise", "appliance", …).
- **FP-UNCLEAR** — no decisive indicator / missing CVE.

## Ground-truth loading & integrity

- `ground_truth.py :: load_ground_truth(path)` — reads the CSV into `Finding[]`,
  normalizing symmetrically; `source="ground-truth"`.
- `gt_hash.py :: compute_gt_hash(path)` — SHA256 over sorted
  `(ecosystem, component, version, cve|osv_id)` payload; used to prove the
  ground truth is fixed across runs ([[decision-0003-immutable-time-fixed-ground-truth]]).

## Metrics (per ecosystem + aggregate)

- **TP** = matched GT entries (exact + range)
- **FP<sub>GT</sub>** = tool findings not matched to GT
- **FN** = GT entries not detected
- **Recall** = `TP / (TP + FN)`
- **Overlap** = `TP / (TP + FP_GT)`

Also emits a binary **GT detection vector** aligned to original GT order (each
TP consumes one GT index), the input to significance testing in
[[analysis-and-significance]].

## Single-tool entry point (`evaluate.py`)

`run_evaluation()` order: load GT → `_init_adapter(tool)` (manual factory) →
`adapter.load_findings()` → dump raw findings → `evaluate_project_centric()` →
FP + FN classification → build detection vector → per-ecosystem metrics →
`write_report()`. Adapters are registered manually in `_init_adapter()` and the
argparse `--tool` choices — no dynamic plugin system
([[decision-0001-adapter-pattern-for-tools]]).

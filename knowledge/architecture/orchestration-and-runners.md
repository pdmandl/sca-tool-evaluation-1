---
title: Orchestration & Runners
type: architecture
module: src/evaluation/orchestration + temporal_runner + tools/
tags: [architecture, module, orchestration, reproducibility, runner]
---

# Orchestration & Runners

This is the layer that turns single evaluations into **reproducible, repeated
experiments** with ground-truth stability checks and cross-run aggregation.

See also: [[overview]], [[evaluation-core]], [[analysis-and-significance]],
[[reporting]], [[decision-0003-immutable-time-fixed-ground-truth]].

## Temporal runner (`src/evaluation/temporal_runner.py`)

`run_temporal()` runs **2 repeats** per invocation over the tools in
`EVAL_TOOLS`:

1. For each repeat, for each tool: isolate a per-tool artifact dir, copy GT +
   SBOM locally, call `run_evaluation(..., return_findings=True,
   return_metrics=True)`.
2. Capture a **repeat-level hash** (`hash_findings()` — SHA256 over sorted
   `ecosystem/component/version/cve|osv_id`) to check repeat stability.
3. Collect the [[evaluation-core|GT detection vector]] per tool per repeat.
4. Concatenate detection vectors → matrix → **Cochran's Q + pairwise McNemar +
   Holm** ([[analysis-and-significance]]).
5. Aggregate metrics (mean/std/CI), collapse repeats, compute significance
   markers vs baseline `oss-index`.
6. Emit LaTeX / JSON / PNG / TXT via [[reporting]] and write `run_status.json`.

## Orchestration package (`src/evaluation/orchestration/`)

| Module | Role |
|---|---|
| `ground_truth_snapshot.py` | Build a GT snapshot via subprocess (`build_multi_ground_truth_dataset`), locate the latest CSV/SBOM/stat, copy them out. |
| `ground_truth_diff.py` | Compare two GT snapshots (GT0 vs GT1): added/removed rows, Jaccard, per-ecosystem summary → `gt_diff_{summary.json,added.csv,removed.csv,report.txt}`. |
| `ground_truth_compare.py` | Same comparison plus SHA256 hashing to assert GT stability. |
| `aggregate_experiments.py` | Aggregate multiple temporal runs (`run_1/`, `run_2/`, …): mean/std across runs, rankings, pairwise deltas → `stats.json`, `aggregated_results.tex`, `ecosystem_summary.tex`, `tool_comparison.{png,json,txt}`. |

## Shell driver (`tools/run_experiment.sh`)

The full experiment loop, `NUM_RUNS` times, with GT-stability retries:

1. Load `.env`, derive a UTC `RUN_ID`, create `run_i/` dirs.
2. Build **GT0** snapshot → CSV + SBOM; hash it.
3. Run `evaluation.temporal_runner` (exit 2 = tool failure → retry).
4. Build **GT1** snapshot; hash it.
5. `ground_truth_diff` GT0↔GT1. **If hashes differ, retry the whole attempt**
   (guards the immutability invariant, [[decision-0003-immutable-time-fixed-ground-truth]]).
6. Copy the stable GT + SBOM to the experiment root.
7. `tools/aggregate_experiment.py` aggregates all runs.
8. Write `experiment_status.txt`.

Helper: `tools/dtrack_prepare.sh` sets up a Dependency-Track project + uploads
the SBOM when `dtrack` is among the evaluated tools.

## Reproducibility guarantees

- Ground truth is **snapshotted twice and diffed** every run; instability forces
  a retry.
- Per-repeat and per-tool artifacts are isolated in their own directories.
- Randomness (balancing/sampling) is seedable via `RANDOM_SEED`; identical GT +
  tool config + tool version ⇒ deterministic, comparable results.

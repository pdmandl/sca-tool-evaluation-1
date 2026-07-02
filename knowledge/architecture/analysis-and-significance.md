---
title: Analysis & Significance
type: architecture
module: src/evaluation/analysis
tags: [architecture, module, statistics, significance, heuristics]
---

# Analysis & Significance

`src/evaluation/analysis/` is the layer that **explains** — it never decides
TP/FP/FN (that is [[evaluation-core]]'s job) and never renders artifacts (that is
[[reporting]]'s job). See [[decision-0007-eval-analysis-reporting-separation]].

See also: [[overview]], [[orchestration-and-runners]], [[glossary]].

## Modules

| Module | Role |
|---|---|
| `significance.py` | Cross-tool statistical tests over GT detection matrices. |
| `statistics.py` | Aggregate repeated runs (mean/std/CI); build LaTeX result tables. |
| `plots.py` | matplotlib PNG renderers (significance heatmap, tool comparison bars). |
| `fp_heuristics.py` | Quality of the FP-flagging heuristic (HTP/HFN/HFP/HTN). |
| `tool_findings.py` | Diagnostic summaries (top components/ecosystems by FP/FN). |

## Significance testing (`significance.py`)

Operates on a detection matrix (observations × tools) built from the binary
[[evaluation-core|GT detection vectors]]:

- **Cochran's Q test** — global null "all tools have equal detection
  probability"; Q compared to χ²(k−1).
- **Pairwise McNemar** — for each tool pair a 2×2 table of discordant detections
  (n₁₀, n₀₁), binomial test of asymmetry.
- **Holm correction** — multiplicity correction across all pairwise p-values →
  `p_adj`.
- `compute_significance_markers(..., baseline="oss-index")` — marks tools that
  significantly beat the baseline (used in LaTeX tables).

## Aggregation (`statistics.py`)

- `aggregate()` — over a list of per-run `{tool: {ecosystem: {metric: value}}}`
  computes mean + std.
- `add_confidence_intervals()` — 95% CI (`1.96·std/√n`).
- `build_gt_summary()` — per-ecosystem components / vulnerabilities / CVEs.
- `write_latex_stats()` / `write_ecosystem_summary_table()` — publication tables.

## FP heuristic quality (`fp_heuristics.py`)

Evaluates the **heuristic**, not the scanner, treating a finding's `fp_class`
flag against its ground-truth TP/FP status:
- HTP = FP correctly flagged, HFN = FP missed, HFP = TP wrongly flagged,
  HTN = TP correctly unflagged.
- Heuristic precision = HTP/(HTP+HFP); recall = HTP/(HTP+HFN).

Only produced when an adapter supports an FP heuristic. Kept strictly separate
from the ground-truth verdict ([[decision-0008-heuristic-vs-ground-truth-separation]]).

## Plots (`plots.py`)

- `plot_significance_matrix()` — n×n heatmap; upper triangle annotated with `*`
  (significant) or `p_adj`.
- `plot_tool_comparison()` — grouped Recall vs Overlap bars per tool.

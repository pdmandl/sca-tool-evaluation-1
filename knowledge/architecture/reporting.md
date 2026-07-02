---
title: Reporting
type: architecture
module: src/evaluation/reporting
tags: [architecture, module, reporting, artifacts]
---

# Reporting

`src/evaluation/reporting/` is the **presentation** layer — it turns evaluation
results into human- and machine-readable artifacts and renders nothing that
isn't already decided upstream ([[decision-0007-eval-analysis-reporting-separation]]).

See also: [[overview]], [[evaluation-core]], [[analysis-and-significance]].

## Modules & artifacts

| Module | Function | Output | Purpose |
|---|---|---|---|
| `evaluation_report.py` | `write_report()` | `{gt_stem}_{tool}_evaluation.txt` | Full report: global summary, per-ecosystem 18-column table, FP/FN classification counts, top-component diagnostics, and FP/FN/TP detail tables. |
| `dump_tool_findings.py` | `dump_tool_findings_csv()` | `{gt_stem}_{tool}_evaluation_findings.csv` | Normalized tool findings in the GT CSV schema (re-ingestible). |
| `tool_findings_txt.py` | `write_tool_findings_txt()` | `{gt}_{tool}_tool_findings.txt` | Fixed-width table of raw normalized findings (ecosystem, component, version, CVE, GHSA, OSV-ID, range, source). |

## Report content notes

- **False negatives have empty descriptions by design** — descriptions come only
  from tool data; the framework does not enrich FN rows from OSV, keeping the
  methodology clean.
- Global summary reports `TP_EXACT`, `TP_RANGE`, `TP_TOTAL`, `FP`<sub>`GT`</sub>,
  `FN`, `Recall`, `Overlap`.

## Temporal / experiment artifacts

Produced by the [[orchestration-and-runners|temporal runner and aggregator]]
(rendered via [[analysis-and-significance]] writers):

- LaTeX: `aggregated_results.tex`, `ecosystem_summary.tex`, `recall_significance.tex`
- JSON: `experimental_results.json`, `recall_significance.json`,
  `tool_comparison_summary.json`, `tool_repeat_comparison.json`, `run_status.json`
- PNG: `tool_comparison.png`, `recall_significance_matrix.png`, `significance_matrix.png`
- TXT: `tool_comparison_summary.txt`, `tool_repeat_comparison.txt`

Archived examples live under `results/paper/`.

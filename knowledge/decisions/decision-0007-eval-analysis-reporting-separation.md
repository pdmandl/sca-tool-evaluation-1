---
title: "ADR-0007: Evaluation / Analysis / Reporting separation"
type: decision
status: accepted (inferred)
tags: [decision, adr, architecture, layering]
---

# ADR-0007: Evaluation / Analysis / Reporting separation

**Status:** Accepted (inferred from code + README architectural invariant)

## Context

Metrics, diagnostics, and presentation tend to bleed together, producing
inconsistent numbers (e.g. a table recomputing recall differently from the
engine).

## Decision

Enforce three layers with a one-directional dependency:

> **Evaluation decides. Analysis explains. Reporting presents.**

- [[evaluation-core]] produces the canonical `(tp_exact, tp_range, fp, fn)` lists
  and the GT detection vector — the **single source of truth**.
- [[analysis-and-significance]] consumes those to compute aggregates,
  significance, and heuristic quality; it never re-decides TP/FP/FN.
- [[reporting]] consumes both to render TXT/CSV/LaTeX/JSON/PNG; it renders
  nothing it computed itself.

## Consequences

- **+** Every artifact traces back to the same verdict; no metric drift.
- **+** Layers are independently testable and replaceable.
- **−** Requires discipline: passing rich result objects between layers rather
  than recomputing locally.
- Pairs with [[decision-0008-heuristic-vs-ground-truth-separation]].

---
title: "ADR-0005: Identifier-gated, project-centric matching (no fuzzy)"
type: decision
status: accepted (inferred)
tags: [decision, adr, matching, evaluation]
---

# ADR-0005: Identifier-gated, project-centric matching (no fuzzy)

**Status:** Accepted (inferred from code)

## Context

Comparing scanner output to ground truth invites fuzzy heuristics (name
similarity, version guessing) that make results hard to defend in a paper. The
framework needs a defensible, deterministic matching rule.

## Decision

Matching in [[evaluation-core]] is **project-centric** and **identifier-gated**:
- A project state is a fixed set of `(ecosystem, component, version)` tuples;
  findings for other versions/components are over-approximation → FP<sub>GT</sub>.
- A tool finding can only match a ground-truth entry if their **identifier sets
  intersect** (`CVE`/`GHSA`/`OSV-ID`). Version match alone never qualifies.
- Version match is either `TP_EXACT` (equal) or `TP_RANGE` (GT version inside a
  reported, parseable range). **No fuzzy string matching anywhere.**
- Normalization is applied **symmetrically** to both sides before comparison.

## Consequences

- **+** Deterministic, explainable verdicts; robust to naming noise.
- **+** Enables the strict FN breakdown `FN_exact → FN_range → FN_true`.
- **−** Tools that report a real vuln under a *different* identifier are scored
  as FN_exact, not TP — strictness can understate a tool.
- **−** Sensitive to normalization correctness (`normalization.py`).
- Complements [[decision-0007-eval-analysis-reporting-separation]].

---
title: "ADR-0008: FP heuristic kept separate from the ground-truth verdict"
type: decision
status: accepted (inferred)
tags: [decision, adr, heuristics, methodology]
---

# ADR-0008: FP heuristic kept separate from the ground-truth verdict

**Status:** Accepted (inferred from code + docs)

## Context

The framework offers a false-positive heuristic (ecosystem/name/CPE/foreign-product
signals). If the heuristic were allowed to alter TP/FP/FN counts, the ground
truth would no longer be the sole authority and results would be circular.

## Decision

The **ground truth decides** TP / FP<sub>GT</sub> / FN; the **FP heuristic only
flags**. The two are strictly separated:
- FP labels (`FP-CERTAIN`/`FP-LIKELY`/`FP-UNCLEAR`) annotate findings but never
  change the ground-truth classification.
- The heuristic is itself *measured* against the ground truth via a confusion
  matrix (HTP/HFN/HFP/HTN → heuristic precision/recall) in
  [[analysis-and-significance]].

> "A heuristic is a hypothesis — not a truth."

## Consequences

- **+** Ground-truth metrics stay objective and reproducible.
- **+** The heuristic can be evaluated and improved as a first-class artifact.
- **−** Two parallel classification vocabularies coexist (a flagged ambiguity in
  the [[glossary]]: bare "FP" is triple-overloaded).
- Extends [[decision-0007-eval-analysis-reporting-separation]].

---
title: "ADR-0003: Immutable, time-fixed ground truth"
type: decision
status: accepted (inferred)
tags: [decision, adr, ground-truth, reproducibility]
---

# ADR-0003: Immutable, time-fixed ground truth

**Status:** Accepted (inferred from code)

## Context

OSV advisories change over time (new CVEs, revised ranges). If the ground truth
tracked OSV live, evaluation results would not be reproducible or comparable
across time.

## Decision

A generated ground truth is **time-fixed and immutable**: at creation it
captures every vulnerability OSV lists for each `(ecosystem, component,
version)` *at build time*, and later OSV updates never retroactively change a
published dataset. Integrity is enforced by:
- `gt_hash.py :: compute_gt_hash()` — a SHA256 fingerprint over the sorted rows;
- the [[orchestration-and-runners|experiment driver]] snapshotting the GT twice
  (GT0/GT1) and **diffing hashes**, retrying the whole attempt if they differ.

## Consequences

- **+** Deterministic, citable datasets (paired with a Zenodo dataset DOI).
- **+** Repeated runs are comparable; significance testing is meaningful.
- **−** Datasets go stale and must be regenerated to reflect newer advisories.
- Builds on [[decision-0002-osv-as-single-source-of-truth]]; supports the
  reproducibility goals in [[overview]].

---
title: "ADR-0004: Deterministic cross-ecosystem balancing"
type: decision
status: accepted (inferred)
tags: [decision, adr, balancing, determinism]
---

# ADR-0004: Deterministic cross-ecosystem balancing

**Status:** Accepted (inferred from code)

## Context

Raw OSV collection yields very uneven per-ecosystem counts, which would bias
aggregate comparisons toward whichever ecosystem happens to be over-represented.
Naive random sampling would break reproducibility.

## Decision

Provide optional **balancing** (`BALANCE`, `BALANCE_STRATEGY=min|median`) via
`balancing.py :: balance_rows_by_vulnerability_deterministic()`:
- hard-cap rows per `(ecosystem, component)` (10) to stop any component
  monopolizing;
- group by component-version, sort each group canonically by
  `(vulnerability_id, cve)`;
- round-robin across queues to select exactly `target` rows per ecosystem while
  preserving component diversity.

The algorithm is **fully deterministic** — no RNG needed; canonical sort order
makes output reproducible. (`RANDOM_SEED` covers any other sampling.)

## Consequences

- **+** Fair cross-ecosystem aggregates; reproducible without a seed.
- **+** Diversity preserved (`MIN_UNIQUE_COMPONENT_RATIO`).
- **−** Balancing discards data; the balanced set is smaller and strategy-dependent.
- Interacts with capping choices; see [[ground-truth-generation]].

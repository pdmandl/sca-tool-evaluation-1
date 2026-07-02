---
title: "ADR-0006: Maven date filtering disabled for determinism"
type: decision
status: accepted (inferred)
tags: [decision, adr, maven, determinism]
---

# ADR-0006: Maven date filtering disabled for determinism

**Status:** Accepted (inferred from code + commit `2b6e84b`)

## Context

Other ecosystems filter candidate versions to the `[START_DATE, END_DATE]`
window using registry publish dates. For Maven, publish timestamps come from
`search.maven.org`, which is rate-limited and returns non-deterministic results,
making the generated ground truth unstable across runs.

## Decision

**Skip date-window filtering for Maven** in `ecosystems/maven.py`. Maven versions
are taken from `maven-metadata.xml` and vulnerability inclusion relies on OSV
advisory data rather than `search.maven.org` date filtering.

## Consequences

- **+** Maven ground truth is deterministic and reproducible (satisfies the
  immutability check in [[decision-0003-immutable-time-fixed-ground-truth]]).
- **−** Maven's version selection is not bounded by the same release-date window
  as PyPI/npm/NuGet — a documented asymmetry across ecosystems.
- See [[ground-truth-generation]] for the per-ecosystem collection behaviour.

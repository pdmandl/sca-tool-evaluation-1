---
title: "ADR-0002: OSV as the single ground-truth authority"
type: decision
status: accepted (inferred)
tags: [decision, adr, osv, ground-truth]
---

# ADR-0002: OSV as the single ground-truth authority

**Status:** Accepted (inferred from code)

## Context

A benchmark needs an authoritative, machine-queryable, multi-ecosystem source of
vulnerability↔version data. Candidates (NVD/CPE, vendor feeds, per-ecosystem
advisories) vary in coverage and version-affectedness precision.

## Context / Decision

Use **OSV.dev** as the sole reference for what counts as a vulnerable
`(ecosystem, component, version)`. [[ground-truth-generation]] queries the OSV
query API per component version and interprets OSV affected-ranges; the `osv`
[[tool-adapters|adapter]] doubles as a reference/validation source that confirms
each ground-truth row still exists in OSV.

## Consequences

- **+** One consistent affectedness model across PyPI/npm/Maven/NuGet;
  identifiers (CVE/GHSA/OSV-ID) come from OSV aliases.
- **+** Ground truth is reproducible from public data.
- **−** The benchmark inherits OSV's coverage gaps and any OSV mislabeling.
- **−** Tools relying on other feeds may be penalized where OSV disagrees.
- Enables the immutability guarantee in
  [[decision-0003-immutable-time-fixed-ground-truth]].

---
title: "ADR-0001: Adapter pattern for SCA tools"
type: decision
status: accepted (inferred)
tags: [decision, adr, adapters, architecture]
---

# ADR-0001: Adapter pattern for SCA tools

**Status:** Accepted (inferred from code)

## Context

The framework must compare heterogeneous SCA tools and advisory sources that
differ wildly in transport (REST, GraphQL, CLI subprocess, SBOM scan), auth, and
output schema. The evaluation engine must not know these differences.

## Decision

Introduce a `VulnerabilityToolAdapter` base class ([[tool-adapters]]) that every
source subclasses. Each adapter hides its transport/quirks and emits the single
normalized [[evaluation-core|Finding]] model. Adapters are registered manually
in a `_init_adapter()` factory and the argparse `--tool` choices — there is no
dynamic plugin discovery.

## Consequences

- **+** New tools integrate by implementing one contract; the evaluation core is
  untouched.
- **+** Shared infra (API/CLI logging, progress, dedup, identifier requirement)
  lives in the base class.
- **−** Adding a tool touches several spots (subclass, import, factory branch,
  CLI choice); no auto-registration.
- Related: [[decision-0005-identifier-gated-project-centric-matching]].

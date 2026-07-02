---
title: Ubiquitous Language / Glossary
type: domain
tags: [domain, glossary, ubiquitous-language, ddd]
---

# Ubiquitous Language

Canonical domain vocabulary for the SCA tool evaluation framework, extracted
from the codebase. Opinionated: where several words denote one concept, one is
chosen and the rest listed as **aliases to avoid**. See [[overview]] for how the
terms fit together; ambiguities are flagged at the bottom.

## Dataset & subjects

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Ground truth** | The immutable, OSV-derived gold-standard set of vulnerable component versions an evaluation is scored against. | gold standard, reference set, GT |
| **Ground-truth observation** | One row: a vulnerable tuple `(ecosystem, component, version, vulnerability_id)`. | GT entry, record, sample |
| **Ecosystem** | A package universe the framework supports: `pypi`, `npm`, `maven`, `nuget` (internal *canonical* names). | registry, package manager |
| **Component** | A package within an ecosystem; Maven components use `group:artifact` form. | package, artifact, library, dependency |
| **Version** | The exact release string of a component; compared verbatim after trimming (no semver coercion). | release, tag |
| **PURL** | Package URL that canonically identifies a component version, e.g. `pkg:pypi/requests@2.31.0`. | coordinate, package id |
| **SBOM** | CycloneDX bill of materials listing exactly the ground-truth component versions; input to SBOM-driven scanners. | bill of materials, manifest |

## Vulnerabilities & identifiers

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Vulnerability** | A security defect affecting a component version, sourced from OSV. | vuln, flaw, issue |
| **Advisory** | The OSV record describing a vulnerability (carries aliases and affected ranges). | report, entry |
| **OSV-ID** | The primary OSV advisory identifier stored in `vulnerability_id` (often a GHSA). | vuln id, advisory id |
| **CVE** | An MITRE CVE identifier; an *alias* of an advisory, not necessarily its primary id. | CVE id |
| **GHSA** | A GitHub Security Advisory identifier. | github id |
| **Identifier** | Any of CVE / GHSA / OSV-ID; the set used to gate matching. | vuln key |

## Tools & findings

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **SCA tool** | A Software Composition Analysis scanner or advisory source under evaluation (Dependency-Track, Snyk, Trivy, OSV, GitHub, OSS Index). | scanner, product, source |
| **Adapter** | The component that queries one SCA tool and normalizes its output into the `Finding` model. | connector, plugin, wrapper |
| **Finding** | A single normalized `(ecosystem, component, version, identifiers)` record; `source` marks it as ground-truth or a specific tool. | result, detection, hit |
| **Normalization** | Symmetric canonicalization of ecosystem/component/version/identifiers applied to *both* sides before matching. | cleaning, sanitizing |

## Matching & classification

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Project-centric matching** | Scoring where a project state is a fixed set of `(ecosystem, component, version)` tuples; findings for other versions count as over-approximation. | file-centric, fuzzy matching |
| **Match type** | How a true positive matched: `TP_EXACT` (same version) or `TP_RANGE` (GT version inside a reported range). | match kind |
| **TP** (True Positive) | A tool finding that matches a ground-truth entry on both identifier and version. | correct hit |
| **FP<sub>GT</sub>** (Ground-truth False Positive) | A tool finding that matches no ground-truth entry. | FP, over-detection |
| **FN** (False Negative) | A ground-truth entry no tool finding matched, split by precedence into `FN_exact → FN_range → FN_true`. | miss |
| **Recall** | `TP / (TP + FN)` — share of the ground truth a tool detected. | sensitivity, detection rate |
| **Overlap** | `TP / (TP + FP`<sub>`GT`</sub>`)` — share of a tool's findings that are true. | precision, overlap rate |
| **GT detection vector** | Binary vector aligned to ground-truth order marking which entries a tool detected; input to significance tests. | hit vector |

## Heuristic evaluation (distinct from ground truth)

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **FP heuristic** | A hypothesis that flags a finding as a likely false positive; measured, never treated as truth. | FP filter, rule |
| **FP class** | The heuristic's label on an FP<sub>GT</sub> finding: `FP-CERTAIN`, `FP-LIKELY`, `FP-UNCLEAR`. | FP type, FP subtype |
| **Heuristic quality (HTP/HFN/HFP/HTN)** | Confusion counts scoring the *heuristic* against the ground-truth verdict, yielding heuristic precision/recall. | heuristic score |

## Experiment orchestration

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Repeat** | One inner iteration of an evaluation for a tool within a temporal run (fixed at 2). | trial |
| **Temporal run** | One pass of the temporal runner over all tools × repeats, producing significance + aggregates. | evaluation run |
| **Experiment** | An outer set of `NUM_RUNS` temporal runs orchestrated by `run_experiment.sh`, aggregated across runs. | campaign, batch |
| **Balancing** | Optional deterministic down-selection so no ecosystem dominates the ground truth. | sampling, downsampling |
| **Capping** | Bounding versions per component or OSV entries per version during collection. | truncation, limiting |

## Relationships

- A **ground truth** contains many **ground-truth observations**, each keyed by
  a vulnerable tuple `(ecosystem, component, version, vulnerability_id)`.
- Every **vulnerability** in the ground truth refers to a **component** version
  that is also present in the **SBOM**, and vice versa (the SBOM invariant).
- An **adapter** wraps exactly one **SCA tool** and emits normalized **findings**.
- The evaluation compares tool **findings** against **ground-truth observations**
  and labels each **TP**, **FP<sub>GT</sub>**, or **FN**; **Recall** and
  **Overlap** are derived from those counts.
- The **ground truth** decides TP/FP/FN; the **FP heuristic** only *flags* — the
  two are kept strictly separate.
- A **temporal run** contains 2 **repeats** per tool; an **experiment** contains
  `NUM_RUNS` **temporal runs**.

## Example dialogue

> **Reviewer:** "Snyk reported `requests 2.31.0` with CVE-2023-32681 — is that a **TP**?"

> **Author:** "Only if that identifier is an **alias** of the **advisory** on the matching **ground-truth observation**. Version match alone isn't enough — matching is **identifier-gated**."

> **Reviewer:** "And if the versions differ but the tool gives a **range**?"

> **Author:** "Then it's a `TP_RANGE` if our version falls inside it. If the tool saw the same version but a *different* identifier, that ground-truth row becomes an `FN_exact`, not an **FP<sub>GT</sub>**."

> **Reviewer:** "The tool also flagged an enterprise-server CVE we don't carry."

> **Author:** "That's an **FP<sub>GT</sub>**. The **FP heuristic** would tag it `FP-LIKELY` because the description names a foreign product — but that flag is a hypothesis; the **ground truth** still owns the verdict."

## Flagged ambiguities

- **"Finding" is overloaded.** One `Finding` dataclass represents *both*
  ground-truth entries and tool findings; only the `source` field distinguishes
  them. When speaking, say "ground-truth observation" vs "tool finding".
- **"Ecosystem" has four spellings.** Internally `pypi`/`npm`/`maven`/`nuget`
  (canonical), but OSV expects `PyPI`/`npm`/`Maven`/`NuGet`, GitHub expects
  `PIP`/`NPM`/`MAVEN`/`NUGET`, and PURL uses its own. `EcosystemMapping` holds
  all four; always specify which naming you mean.
- **"FP" is triple-overloaded.** (1) **FP<sub>GT</sub>** — a ground-truth false
  positive from the scanner; (2) **FP class** — the heuristic's guess about a
  finding; (3) **HFP** — a true positive the heuristic *wrongly* flagged. Never
  write a bare "FP".
- **"Vulnerability" vs `vulnerability_id`.** `vulnerability_id` is the OSV
  advisory id (often a GHSA), not a CVE. The CVE lives in the separate `cve`
  column as an alias.
- **"Run" is a hierarchy.** *repeat* ⊂ *temporal run* ⊂ *experiment*. Reserve
  each word for its level; "run" alone is ambiguous.
- **"Overlap" means precision.** It is the paper's chosen term for
  `TP/(TP+FP`<sub>`GT`</sub>`)`; don't silently substitute "precision" in code or
  tables where "Overlap" is the column name.
- **"Match type" (`EXACT`/`RANGE`) vs classification (`TP_EXACT`/`TP_RANGE`).**
  The OSV adapter stamps a raw `match_type`; the evaluator assigns the
  `TP_EXACT`/`TP_RANGE` label. Related but produced at different layers.

---
title: Architecture Overview
type: architecture
tags: [architecture, overview, sca, benchmark]
---

# Architecture Overview

**sca-tool-evaluation** is a research-grade framework for (1) generating an
OSV-based, multi-ecosystem vulnerability **ground truth** and (2) **benchmarking
Software Composition Analysis (SCA) tools** against it with repeated runs,
aggregation, and statistical significance testing.

It is *not* a scanner and *not* an SBOM generator — it is an **evaluation and
comparison** harness. See the domain [[glossary]] for terminology.

## The two halves

```
┌─────────────────────────┐        CSV ground truth  ┌────────────────────────────┐
│  Ground-Truth Generator │  ───▶  + CycloneDX SBOM   │  Evaluation & Benchmarking │
│  (OSV-based)            │                           │  (project-centric)         │
└─────────────────────────┘                           └────────────────────────────┘
```

1. **[[ground-truth-generation]]** — collects vulnerable `(ecosystem, component,
   version, vulnerability_id)` observations from OSV across PyPI, npm, Maven,
   NuGet; emits an immutable CSV + matched SBOM + statistics + metadata.
2. **[[tool-adapters]]** — normalize findings from six SCA tools / advisory
   sources into one `Finding` model.
3. **[[evaluation-core]]** — matches tool findings against ground truth and
   classifies TP / FP<sub>GT</sub> / FN.
4. **[[analysis-and-significance]]** — explains findings (FP/FN diagnostics, FP
   heuristic quality) and computes cross-tool significance.
5. **[[reporting]]** — presents results as TXT / CSV / LaTeX / JSON / PNG.
6. **[[orchestration-and-runners]]** — the temporal runner and shell driver that
   tie it all together for reproducible, repeated experiments.

## Layered invariant

The pipeline enforces a strict separation of concerns
([[decision-0007-eval-analysis-reporting-separation]]):

> **Evaluation decides. Analysis explains. Reporting presents.**

Each layer consumes only the output of the layer above. Normalization is applied
**symmetrically** to both the ground-truth side and the tool side
([[decision-0005-identifier-gated-project-centric-matching]]).

## End-to-end data flow

```
[curated package lists] ─▶ ecosystems/*.py ─▶ OSV query API
                                              │
                          canonicalize/cap/validate/balance
                                              ▼
             ground-truth CSV  +  CycloneDX SBOM  +  stat.txt  +  meta.json
                                              │
        ┌─────────────────────────────────────┴────────────────────┐
        ▼ (SBOM / API / CLI)                                        ▼
   tool adapters  ──▶  normalized Finding[]  ──▶  evaluate_project_centric()
                                              │      → (tp_exact, tp_range, fp, fn)
                                              ▼
              FP/FN classification, per-ecosystem metrics (Recall, Overlap)
                                              │
        repeated (temporal_runner, 2 repeats) → GT detection vectors
                                              ▼
        Cochran's Q + pairwise McNemar + Holm  ──▶  LaTeX / JSON / PNG / TXT
```

## Entry points

| Entry point | Purpose |
|---|---|
| `python -m ground_truth_generation.build_multi_ground_truth_dataset` | Build a ground-truth dataset (env-driven). |
| `python -m evaluation.evaluate --ground-truth <csv> --tool <t>` | Evaluate a single tool. |
| `python -m evaluation.temporal_runner --ground-truth <csv> --sbom <json> --output <dir>` | Repeated multi-tool evaluation + significance. |
| `tools/run_experiment.sh` | Full experiment: GT snapshot → temporal eval → GT-stability diff → cross-run aggregation. |
| `tools/aggregate_experiment.py` | Aggregate multiple temporal runs. |

## Build / test / tooling

- **Python 3.12**, **Poetry** project; sources under `src/` (`pythonpath = src`).
- Key deps: `requests`, `packaging`, `semantic-version`, `scipy`/`numpy`
  (significance), `matplotlib` (plots), `cyclonedx-python-lib` (SBOM), `tqdm`.
- `Makefile` targets: `install`, `test`, `coverage`, `lint`, `format`, `sbom`,
  `sonar`, `clean`.
- **CI** (`.github/workflows/ci.yml`): ruff lint + pytest with coverage on
  Python 3.12.
- Config is heavily **environment-variable driven** for reproducibility (see
  `.env_example`, README).

## Notable decisions

- [[decision-0001-adapter-pattern-for-tools]]
- [[decision-0002-osv-as-single-source-of-truth]]
- [[decision-0003-immutable-time-fixed-ground-truth]]
- [[decision-0004-deterministic-balancing]]
- [[decision-0005-identifier-gated-project-centric-matching]]
- [[decision-0006-maven-date-filter-disabled]]
- [[decision-0007-eval-analysis-reporting-separation]]
- [[decision-0008-heuristic-vs-ground-truth-separation]]

# Archived Results

This directory contains the evaluation artifacts referenced in the paper, plus
a reference SBOM and a test-coverage report for the framework itself. The data
is archived here so reviewers and readers can inspect the exact numbers cited
in the paper without re-running the full pipeline (which requires credentials
for several SCA services).

---

## Evaluation Setup

### Ground-Truth Dataset

The ground-truth dataset is an OSV-derived snapshot that resolves
vulnerabilities to explicit package-version tuples *(ecosystem, component,
version, vulnerability-id)* across four package ecosystems.

| Ecosystem | Components | OSV entries | CVE-backed findings | Distinct CVEs |
|-----------|-----------:|------------:|--------------------:|--------------:|
| Maven     | 99         | 250         | 240                 | 42            |
| npm       | 66         | 250         | 231                 | 19            |
| NuGet     | 189        | 250         | 250                 | 36            |
| PyPI      | 76         | 250         | 203                 | 92            |
| **Total** | **430**    | **1 000**   | **924**             | **189**       |

The dataset is balanced with respect to the number of OSV entries per
ecosystem (250 each), but not with respect to component or CVE diversity.

### Evaluated Tools

Five representative systems were evaluated, covering open-source and
commercial offerings, full SCA platforms and pure advisory services:

| Tool | Version | Access mode | Input |
|------|---------|-------------|-------|
| OWASP Dependency-Track | 4.14.3 | REST API | CycloneDX SBOM |
| Snyk | 1.1301.2 | CLI / backend API | CycloneDX SBOM |
| Sonatype OSS Index | v3 | REST API | Package coordinates |
| GitHub Advisory Database | current GraphQL schema | GraphQL API | Package name + version |
| Trivy | v0.69.1 | CLI | CycloneDX SBOM |

Dependency-Track, Snyk, and Trivy received identical deterministically
generated CycloneDX SBOMs. OSS Index and the GitHub Advisory Database were
queried directly with package and version coordinates.

### Evaluation Metrics

Each tool finding is classified relative to the OSV-derived ground truth:

| Symbol | Definition |
|--------|-----------|
| **TP** | Vulnerability correctly reported by the tool (present in ground truth) |
| **FP<sub>GT</sub>** | Vulnerability reported by the tool but absent from the ground truth |
| **FN** | Vulnerability present in the ground truth but not detected by the tool |

> **Note on FP<sub>GT</sub>:** A ground-truth-relative false positive does not
> necessarily mean the reported finding is wrong. It may reflect a legitimate
> vulnerability not yet included in the OSV snapshot, an advisory present in
> other databases but absent from OSV, or a difference in version-range
> interpretation. The label is relative to the current ground-truth snapshot.

Two primary metrics are reported:

```
Recall  = TP / (TP + FN)       — completeness relative to the ground truth
Overlap = TP / (TP + FP_GT)    — selectivity relative to the ground truth
```

---

## Key Results (2026-03-28 snapshot)

### Overall per-tool results

| Tool | TP | FP<sub>GT</sub> | FN | Recall | Overlap |
|------|---:|----------------:|---:|-------:|--------:|
| Trivy | 961 | 326 | 39 | **0.96** | 0.78 |
| GitHub Advisory | 948 | 931 | 52 | 0.95 | 0.54 |
| OWASP Dependency-Track | 907 | 322 | 93 | 0.91 | 0.77 |
| Snyk | 902 | 496 | 98 | 0.90 | 0.71 |
| OSS Index | 614 | 237 | 386 | 0.61 | **0.80** |

Trivy achieves the strongest overall balance: highest recall (0.96) with
comparatively strong overlap (0.78). The GitHub Advisory Database reaches
nearly the same recall (0.95) but at the cost of substantially more
FP<sub>GT</sub>, reducing its overlap to 0.54. OWASP Dependency-Track (0.91)
and Snyk (0.90) form a second group with strong recall. OSS Index shows the
weakest recall (0.61) but the highest overlap (0.80), indicating a more
conservative reporting strategy.

### Per-ecosystem summary (averaged across all tools)

| Ecosystem | Mean Recall | Mean Overlap | Mean FP<sub>GT</sub> | Mean FN |
|-----------|------------:|-------------:|---------------------:|--------:|
| Maven     | 0.85        | 0.52         | 225.4                | 37.4    |
| npm       | 0.83        | 0.83         | 54.8                 | 42.0    |
| NuGet     | 0.94        | 0.93         | 24.2                 | 14.8    |
| PyPI      | 0.84        | 0.60         | 158.0                | 39.4    |

NuGet is the least challenging ecosystem (highest mean recall and overlap).
Maven shows the largest average FP<sub>GT</sub> burden and the lowest mean
overlap, indicating that precise version-level matching is particularly
difficult there.

### Statistical significance

Cochran's *Q* test on the paired binary detection matrix confirms a highly
significant overall difference in recall across tools (*Q* = 1452.81,
*p* < 0.001). Pairwise post-hoc exact McNemar tests with Holm correction
identify the following groups:

| Pair | *p*<sub>adj</sub> | Significant? |
|------|------------------:|:---:|
| GitHub vs. Trivy | 0.104 | No |
| OWASP Dependency-Track vs. Snyk | 0.642 | No |
| All other pairs | < 0.001 | Yes |

GitHub and Trivy form a statistically indistinguishable top recall group.
Dependency-Track and Snyk form a statistically indistinguishable middle group.
OSS Index is significantly weaker than all other tools.

---

## Layout

```
results/
├── paper/                    # evaluation runs reported in the paper
│   ├── Test_for_Paper_ready_01_20260328T152709Z/
│   ├── Test_for_Paper_ready_02_20260328T165907Z/
│   ├── Test_for_Paper_ready_03_20260328T184035Z/
│   └── Additional_Test_for_paper_ready_after_2_weeks_20260410T072620Z/
├── sbom/                     # CycloneDX SBOM of the framework itself
│   ├── sbom.json
│   └── sbom.xml
└── coverage/                 # pytest coverage report (XML, Cobertura format)
    └── coverage.xml
```

## `paper/` — evaluation runs

The three `Test_for_Paper_ready_0{1,2,3}_20260328…` directories are the
repeated runs used for the main results in the paper (2026-03-28). The
`Additional_Test_for_paper_ready_after_2_weeks_20260410…` directory contains a
comparison run executed two weeks later against refreshed vulnerability feeds,
used to discuss temporal stability.

### What is included per run

Top-level:

- `aggregated_results.tex`, `ecosystem_summary.tex` — LaTeX tables used in the paper
- `stats.json` — aggregated numerical results (TP, FP<sub>GT</sub>, FN, Recall, Overlap per tool and ecosystem)
- `tool_comparison.png` — bar chart of TP / FP<sub>GT</sub> / FN per tool
- `ground_truth.csv` — the exact ground-truth snapshot used for this run
- `sbom.json` — CycloneDX SBOM of the evaluation targets
- `experiment_status.txt`, `ground_truth.stat.txt` — pipeline provenance

`run_1/`:

- `results.json` — per-tool, per-ecosystem results
- `recall_significance.{json,tex,png}`, `significance_matrix.png` — pairwise
  McNemar tests with Holm correction
- `tool_comparison*`, `tool_repeat_comparison*` — repeat-level stability summaries
- `gt_comparison/` — ground-truth self-consistency diagnostics

`run_1/artifacts/repeat_{1,2}/<tool>/`:

- `*_tool_findings.txt` — raw findings returned by each SCA tool for that
  repeat (sufficient to reproduce the TP/FP<sub>GT</sub>/FN classification offline)
- `*_evaluation.txt` — the classification decision per finding

### What has been removed from the archived copy

To keep the archive lightweight and free of credentials:

- `*_api.log` (per-tool HTTP traces) — stripped (contain URLs, headers)
- `ground_truth_build/` (intermediate collection state) — not needed once the
  final `ground_truth.csv` is present
- `run.log`, `<run_id>.log` (pipeline logs) — stripped

---

## `sbom/` — framework SBOM

`sbom.json` / `sbom.xml` describe the Python dependencies of the framework
itself (generated by `cyclonedx-py`). Use them when reviewing the supply chain
of the evaluation tool.

## `coverage/` — framework test coverage

`coverage.xml` is a Cobertura-format coverage report for `tests/`, produced by
`pytest --cov`. It documents which parts of the framework are covered by the
test suite shipped with the repository.

---

## Reproducibility

The numbers in the archived runs can be recomputed from scratch with the
public pipeline (`make evaluate`), but results will differ from the archived
ones in two controlled ways:

1. **Vulnerability data drift.** Public vulnerability databases (OSV, GHSA,
   OSS Index, Snyk, Trivy) add and retract advisories continuously. A fresh
   run therefore classifies some findings differently from the 2026-03-28
   snapshot.
2. **Sampling randomness.** Ground-truth collection down-samples packages and
   versions; fixing `RANDOM_SEED` in `.env` yields a deterministic package
   set, but the set of *vulnerable* versions within those packages still
   depends on the live databases at collection time.

For exact reproducibility of the paper's tables and plots, read the archived
`stats.json` / `aggregated_results.tex` here rather than re-running.

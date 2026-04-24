# Evaluation Tool for SCA Benchmarking

A reproducible framework for generating OSV-based ground-truth datasets and benchmarking Software Composition Analysis (SCA) tools against them.

## Overview

This repository provides two tightly integrated capabilities:

1. **Ground-truth generation** for multi-ecosystem vulnerability datasets based on package- and version-specific OSV observations.
2. **Evaluation and comparative benchmarking** of SCA tools against that ground truth, including repeated runs, aggregation, reporting, and statistical significance analysis.

The framework is intended for research-grade reproducibility. It supports:
- generation of versioned ground-truth datasets,
- normalization of findings from multiple SCA tools and advisory sources,
- project-centric matching against ground truth,
- calculation of `TP`, `FP`<sub>`GT`</sub>, `FN`, `Recall`, and `Overlap`,
- diagnostic false-positive and false-negative analysis,
- repeated temporal runs with aggregation and significance testing,
- export of machine-readable and publication-ready artifacts.

## Main Capabilities

### Ground-truth generation
- Collects vulnerable package/version observations across multiple ecosystems
- Enriches rows with OSV-backed vulnerability descriptions
- Canonicalizes vulnerability entries
- Optionally applies balancing and safe capping
- Validates rows against cached OSV query results
- Generates:
  - CSV dataset
  - statistics report
  - CycloneDX SBOM
  - metadata file

### Evaluation
- Loads and normalizes findings via tool-specific adapters
- Evaluates findings against a fixed ground-truth dataset
- Computes per-ecosystem and aggregated metrics
- Produces evaluation reports and finding dumps
- Supports repeated runs for cross-tool comparison and repeat consistency analysis

### Statistical analysis
- Aggregates repeated runs
- Builds ground-truth detection vectors
- Computes:
  - Cochran’s Q test
  - pairwise McNemar tests
  - Holm correction
- Exports:
  - LaTeX tables
  - JSON summaries
  - TXT summaries
  - PNG plots

## Supported Ecosystems

The current ground-truth generation pipeline supports:
- `pypi`
- `npm`
- `maven`
- `nuget`

## Integrated Adapters

The current evaluation pipeline includes adapters for:
- Dependency-Track (`dtrack`)
- OSV (`osv`)
- GitHub Advisory Database (`github`)
- Snyk (`snyk`)
- OSS Index (`oss-index`)
- Trivy (`trivy`)

> Note: If your local branch contains additional adapters, make sure the public documentation matches the actually wired release version.

## Repository Structure

```text
.
├── src/
│   └── evaluation/
│       ├── adapters/
│       │   ├── dtrack.py
│       │   ├── github_advisory.py
│       │   ├── oss_index.py
│       │   ├── osv.py
│       │   ├── snyk.py
│       │   └── trivy.py
│       ├── analysis/
│       ├── core/
│       ├── orchestration/
│       ├── reporting/
│       ├── __init__.py
│       ├── evaluate.py
│       ├── temporal_runner.py
│       └── ...
├── ground_truth_generation/
├── build_multi_ground_truth_dataset.py
├── docs/
│   └── README_tool_evaluation.md  # adapter details, metrics, FP<sub>GT</sub> heuristic reference
├── results/
│   ├── paper/         # archived evaluation runs referenced by the paper
│   ├── sbom/          # CycloneDX SBOM of the framework
│   └── coverage/      # pytest coverage report (Cobertura XML)
├── pyproject.toml
├── README.md
├── LICENSE
├── CITATION.cff
└── .zenodo.json
```

Archived paper results, the framework SBOM, and the coverage report are
bundled under [`results/`](results/README.md) so reviewers can inspect the
exact numbers cited in the paper without rerunning the pipeline.

## Installation

This is a **Poetry** project.

### 1. Clone the repository

```bash
git clone https://github.com/prcmandl/sca-tool-evaluation.git
cd sca-tool-evaluation
```

### 2. Install dependencies

```bash
poetry install
```

### 3. Configure `src` as source root

The project source code lives under `src/`. When working in an IDE (e.g. PyCharm), mark the `src/` directory as **Sources Root** so that all modules under `evaluation/` and `ground_truth_generation/` are resolved correctly.

In PyCharm: right-click the `src/` folder → *Mark Directory as* → *Sources Root*.

For pytest, this is handled automatically via the `pythonpath = src` setting in `pyproject.toml`.

### 4. Run commands inside the Poetry environment

Either activate the environment:

```bash
poetry shell
```

or run commands directly via:

```bash
poetry run <command>
```

## Prerequisites for Full Evaluation

Running all SCA tool adapters requires the following external tools and services to be set up:

### Tool installation

The following tools must be installed locally before their respective adapters can be used:

| Tool | Installation |
|---|---|
| **Snyk CLI** | `npm install -g snyk` — then authenticate (see below) |
| **Trivy** | https://aquasecurity.github.io/trivy/latest/getting-started/installation/ |

> **Snyk authentication required before every use**
>
> After installation, run `snyk auth` once to log in. The CLI opens a browser
> window to complete OAuth authentication against your Snyk account. The session
> token is stored locally (`~/.config/snyk/snyk.json`); it expires after a
> period of inactivity. If `snyk` is included in `EVAL_TOOLS` and authentication
> has not been completed, the Snyk adapter will fail silently or return zero
> findings — run `snyk auth` again to refresh the token.
>
> A free Snyk account is sufficient for SBOM-based scanning. Sign up at
> https://app.snyk.io/login if you do not yet have an account.

### Dependency-Track instance

If `dtrack` is part of `EVAL_TOOLS`, a running Dependency-Track instance is required:
- Deploy Dependency-Track (e.g. via Docker: https://docs.dependencytrack.org/getting-started/deploy-docker/)
- Create an API key under *Administration → Access Management → API Keys*
- Set `DTRACK_URL` and `DTRACK_API_KEY` in your `.env` file

### API credentials

The following advisory sources require credentials or tokens:

| Source | How to obtain |
|---|---|
| **GitHub Advisory Database** | Create a personal access token at https://github.com/settings/tokens (read-only scope is sufficient); set as `GITHUB_TOKEN` |
| **OSS Index (Sonatype)** | Register at https://ossindex.sonatype.org, generate a user token under *Settings*; set `OSSINDEX_USERNAME` and `OSSINDEX_TOKEN` |
| **OSV** | No authentication required; the public OSV API is used directly |

## Quick Start

### 1. Generate a ground-truth dataset

```bash
export GROUND_TRUTH_BUILD_PATH=./artifacts/ground-truth
export SAMPLES=1000
export ECOSYSTEMS="nuget maven pypi npm"
export START_DATE=2020-01-01
export END_DATE=2026-01-25
export BALANCE=false
export BALANCE_STRATEGY=min
export MIN_UNIQUE_COMPONENT_RATIO=0.5

poetry run python -m ground_truth_generation.build_multi_ground_truth_dataset
```

Typical generated artifacts:
- `*.csv`
- `*.stat.txt`
- `*.sbom.json`
- `*.meta.json`

### 2. Evaluate a single tool against a fixed ground truth

```bash
poetry run python -m evaluation.evaluate \
  --ground-truth ./artifacts/ground-truth/mixed_ground_truth_dataset.csv \
  --tool oss-index
```

### 3. Run repeated temporal evaluation across multiple tools

```bash
export EVAL_TOOLS="dtrack oss-index github snyk trivy"

poetry run python -m evaluation.temporal_runner \
  --ground-truth ./artifacts/ground-truth/mixed_ground_truth_dataset.csv \
  --sbom ./artifacts/ground-truth/mixed_ground_truth_dataset.sbom.json \
  --output ./artifacts/temporal-run
```

## Main Entry Points

### `build_multi_ground_truth_dataset.py`

Builds a mixed-ecosystem OSV-based ground-truth dataset.

Main tasks:
- collect vulnerable package/version observations per ecosystem,
- query and enrich OSV-backed vulnerability data,
- canonicalize vulnerability entries,
- optionally apply balancing and capping,
- validate rows against cached OSV responses,
- generate CSV, statistics, SBOM, and metadata outputs.

### `evaluation.evaluate`

Runs a single evaluation for one tool against one ground-truth CSV.

Main tasks:
- load the ground truth,
- initialize the selected adapter,
- normalize tool findings,
- evaluate tool findings against ground truth,
- compute `TP`, `FP`<sub>`GT`</sub>, `FN`, `Recall`, and `Overlap`,
- classify diagnostic false positives and false negatives,
- write reports and normalized finding dumps.

### `evaluation.temporal_runner`

Runs repeated evaluations across multiple tools and aggregates the results.

Main tasks:
- repeat the evaluation workflow across tools,
- capture repeat-level finding hashes,
- build GT detection vectors,
- aggregate per-ecosystem metrics,
- compute significance tests,
- export comparison summaries, plots, JSON payloads, and LaTeX tables.

## Ground-Truth Data Model

The generated ground truth is organized around vulnerable component-version observations.

A typical row contains:
- `ecosystem`
- `component_name`
- `component_version`
- `purl`
- `vulnerability_id`
- `cve`
- `vulnerability_description`
- `is_vulnerable`

In conceptual terms, a ground-truth observation corresponds to a vulnerable tuple of the form:

```text
(ecosystem, component_name, component_version, vulnerability_id)
```

## Evaluation Methodology

The evaluation is **project-centric**: a project state is a fixed set of (ecosystem, component, version) tuples. Tools are expected to report vulnerabilities only for those exact pairs; findings for other versions or components are treated as over-approximation and counted as false positives.

### Ground-truth invariant

At dataset creation time, the ground truth contains every vulnerability that the OSV reference database lists as affecting a given (ecosystem, component, version). The dataset is **time-fixed and immutable** — later OSV updates do not retroactively change a published ground truth.

### Matching semantics

A tool finding `(e, c, v', I')` is compared to a ground-truth entry `(e, c, v, I)` using:

- **Identifier match:** `I ∩ I' ≠ ∅` (at least one CVE, GHSA, or OSV-ID in common).
- **Version match:**
  - `TP_EXACT` — `v' == v`
  - `TP_RANGE` — `v ∈ range(v')` when the tool reports an affected version range

No fuzzy string matching is used anywhere in the pipeline.

### Classification

- **TP** — tool finding matches a ground-truth entry (identifier + version)
- **FP<sub>GT</sub>** — tool finding matches no ground-truth entry
- **FN** — ground-truth entry has no matching tool finding

False negatives are further broken down with a strict precedence:

`FN_exact  →  FN_range  →  FN_true`

- `FN_exact` — tool reported the same `(c, v)` but with non-matching identifiers
- `FN_range` — tool reported only ranges that cannot be safely decided
- `FN_true`  — tool reported nothing relevant for `(c, v)`

### Architectural invariant

The pipeline is organized as three concerns with strict separation:

> **Evaluation decides. Analysis explains. Reporting presents.**

Each layer consumes only the output of the layer above; normalization is applied symmetrically on ground-truth and tool sides (see `evaluation/core/normalization.py`).

### Reproducibility guarantee

Given identical ground truth, tool configuration, and tool version, the framework produces deterministic, comparable results. Randomness (balancing, sub-sampling) is controlled via `RANDOM_SEED`.

## Evaluation Metrics

The evaluation pipeline computes, at minimum, the following per ecosystem:

- `Components`
- `Vulnerabilities`
- `CVEs`
- `TP`
- `FP`<sub>`GT`</sub>
- `FN`
- `Recall`
- `Overlap`

Interpretation:
- **Recall** = `TP / (TP + FN)`
- **Overlap** = `TP / (TP + FP`<sub>`GT`</sub>`)`

The pipeline also builds a binary ground-truth detection vector aligned with the original ground-truth order for significance analysis across repeated runs.

## Output Artifacts

### Ground-truth generation

Typical output files:
- `mixed_ground_truth_dataset_<timestamp>_<components>_<vulns>.csv`
- `mixed_ground_truth_dataset_<timestamp>_<components>_<vulns>.stat.txt`
- `mixed_ground_truth_dataset_<timestamp>_<components>_<vulns>.sbom.json`
- `mixed_ground_truth_dataset_<timestamp>_<components>_<vulns>.meta.json`

### Single-tool evaluation

Typical outputs include:
- normalized tool findings dump
- evaluation report
- per-tool metrics and diagnostics

### Temporal evaluation

Typical output files:
- `experimental_results.json`
- `aggregated_results.tex`
- `ecosystem_summary.tex`
- `recall_significance.tex`
- `recall_significance.json`
- `recall_significance_matrix.png`
- `significance_matrix.png`
- `tool_comparison.png`
- `tool_comparison_summary.json`
- `tool_comparison_summary.txt`
- `tool_repeat_comparison.json`
- `tool_repeat_comparison.txt`
- `run_status.json`
- `run.log`

## Configuration

The project is intentionally environment-driven to support reproducible experiments and archived runs.

### Core ground-truth generation variables

| Variable | Required | Example | Description |
|---|---:|---|---|
| `GROUND_TRUTH_BUILD_PATH` | yes | `./artifacts/ground-truth` | Output directory for generated ground-truth artifacts |
| `SAMPLES` | yes | `1000` | Number of samples collected per ecosystem before downstream processing |
| `ECOSYSTEMS` | yes | `"nuget maven pypi npm"` | Space-separated list of ecosystems to include |
| `START_DATE` | no | `2020-01-01` | Lower bound on release dates |
| `END_DATE` | no | `2026-01-25` | Upper bound on release dates |
| `BALANCE` | no | `true` / `false` | Enables or disables post-hoc balancing |
| `BALANCE_STRATEGY` | no | `min` / `median` | Balancing strategy |
| `MIN_UNIQUE_COMPONENT_RATIO` | no | `0.5` | Diversity-oriented balancing parameter |
| `MAX_COMPONENT_VERSIONS_PER_COMPONENT` | no | `10` | Safe cap for retained versions per component |

### Collector-specific optional variables

Depending on the enabled ecosystem collectors, the generation workflow may also use variables such as:
- `PYPI_MAX_VERSIONS_PER_PACKAGE`
- `NPM_MAX_VERSIONS_PER_PACKAGE`
- `MAVEN_MAX_VERSIONS_PER_PACKAGE`
- `NUGET_MAX_VERSIONS_PER_PACKAGE`

These are especially relevant when reproducing the exact dataset composition used in a paper or archived release.

### Temporal evaluation variables

| Variable | Required | Example | Description |
|---|---:|---|---|
| `EVAL_TOOLS` | no | `"dtrack oss-index github snyk trivy"` | Space-separated tool list for repeated evaluation |
| `EVAL_PROGRESS` | no | `1` / `0` | Enables or disables tqdm-based progress output |

### Internally managed artifact-location variables

During repeated evaluation runs, the pipeline temporarily assigns tool-local artifact directories through:
- `EVAL_ARTIFACTS_DIR`
- `TOOL_OUTPUT_DIR`
- `OUTPUT_DIR`
- `GROUND_TRUTH_BUILD_PATH`

In most cases, these do not need to be set manually.

### Tool-specific adapter variables

Tool adapters typically require their own environment variables, such as:
- API base URLs
- API tokens
- project identifiers
- organization identifiers
- local artifact paths

Because these are adapter-specific, document them in one of the following places for your public release:
- `docs/`
- example `.env` files
- CI templates
- adapter-specific usage notes

A practical publication setup is:
- commit a `.env.example` file with placeholder names and no secrets,
- load secrets locally via shell exports or an ignored `.env` file,
- never commit real tokens or private URLs.



## Environment Setup and `.env` Configuration

The project uses environment variables extensively for reproducible experiment setup, ground-truth generation, adapter configuration, and publication-ready reruns. A practical setup is to maintain a local `.env` file and export its variables before running the pipeline.

A fully documented template is provided via `.env_example`. For local use, copy it to a non-versioned `.env` file, replace all placeholder values, and export the variables into your shell session.

### Recommended usage pattern

```bash
cp .env_example .env
# edit .env and replace placeholder values
set -a
source .env
set +a
```

> Never commit real credentials, tokens, or private URLs to version control.

### Project path variables

These variables define the project-local directory structure used by the orchestration and reporting workflow.

| Variable | Example | Description |
|---|---|---|
| `CODEBASE` | `/path/to/sca_tool_evaluation` | Absolute path to the project root directory |
| `CODEBASE_BUILD_PATH` | `${CODEBASE}/build` | Build base directory for generated artifacts |
| `REPORT_PATH` | `${CODEBASE_BUILD_PATH}/reports` | Report output directory |
| `EXPERIMENT_PATH` | `${CODEBASE_BUILD_PATH}/experiments` | Root directory for experiment runs |

#### Important note on `GROUND_TRUTH_BUILD_PATH`

In newer runner setups, `GROUND_TRUTH_BUILD_PATH` is often assigned dynamically per run or per tool-specific artifact directory. In those setups, it should **not** be configured statically in `.env` unless you intentionally run an older workflow that still expects a fixed path.

### API tokens and credentials

These variables are required only for the adapters or services you actually use.

| Variable | Description |
|---|---|
| `GITHUB_TOKEN` | GitHub API token for GitHub-backed evaluation or enrichment |
| `OSSINDEX_TOKEN` | OSS Index API token |
| `OSSINDEX_USERNAME` | OSS Index username or account email |

### Ground-truth generation: global controls

These variables define the overall collection and balancing behavior of the ground-truth generation pipeline.

| Variable | Example | Description |
|---|---|---|
| `SAMPLES` | `1000` | Number of candidate packages or components considered per ecosystem |
| `START_DATE` | `2020-01-01` | Lower bound of the version selection window |
| `END_DATE` | `2026-01-25` | Upper bound of the version selection window |
| `ECOSYSTEMS` | `"nuget maven pypi npm"` | Space-separated list of included ecosystems |
| `BALANCE` | `false` | Enables or disables post-hoc balancing |
| `BALANCE_STRATEGY` | `min` | Balancing strategy such as `min` or `median` |
| `RANDOM_SEED` | `42` | Optional seed for reproducibility in balancing or sampling logic |

### Ground-truth generation: version sampling per ecosystem

These variables bound the number of versions considered per package or artifact during collection.

| Variable | Example | Description |
|---|---|---|
| `MAVEN_MAX_VERSIONS_PER_PACKAGE` | `30` | Maximum number of Maven versions per artifact |
| `PYPI_MAX_VERSIONS_PER_PACKAGE` | `3` | Maximum number of PyPI versions per package |
| `NPM_MAX_VERSIONS_PER_PACKAGE` | `20` | Maximum number of npm versions per package |
| `NUGET_MAX_VERSIONS_PER_PACKAGE` | `50` | Maximum number of NuGet versions per package |

### Ground-truth generation: vulnerability sampling

These variables influence how many vulnerability observations are retained during collection.

| Variable | Example | Description |
|---|---|---|
| `MAX_OSV_ENTRIES_PER_COMPONENT` | `20` | Maximum number of OSV matches retained per concrete component version |
| `TARGET_VULNS_PER_ECOSYSTEM` | `250` | Optional target number of vulnerabilities per ecosystem |
| `EARLY_STOP_ON_TARGET_VULNS` | `0` | Stops collection early once the target count is reached if enabled |

### Tool selection

The temporal runner reads the following variable to determine which tools to execute.

| Variable | Example | Description |
|---|---|---|
| `EVAL_TOOLS` | `"snyk oss-index github trivy dtrack"` | Space-separated list of tools used in repeated evaluation |

### Dependency-Track variables

These variables are required if `dtrack` is part of `EVAL_TOOLS`.

| Variable | Example | Description |
|---|---|---|
| `DTRACK_URL` | `http://your-dtrack-host:8081` | Dependency-Track base URL |
| `DTRACK_API_KEY` | `***` | Dependency-Track API key |
| `DTRACK_PROJECT_UUID` | `""` | Optional fixed project UUID, often left empty in newer setups |
| `DTRACK_PROJECT_NAME` | `""` | Project name, often assigned dynamically by the runner |
| `DTRACK_PROJECT_VERSION` | `"1.0"` | Project version, often defaulted or overridden dynamically |

### Additional adapter-specific variables

Some adapters or helper workflows may use further variables, for example:

| Variable | Example | Description |
|---|---|---|
| `OSV_ROOT_PATH` | `/path/to/local/osv/vulnfeeds` | Local OSV mirror or feed root if used |
| `SNYK_BIN` | `/usr/local/bin/snyk` | Path to the Snyk executable |

### Execution and experiment control

These variables influence multi-run orchestration and result export.

| Variable | Example | Description |
|---|---|---|
| `NUM_RUNS` | `1` | Number of outer experiment runs |
| `ARCHIVE_RESULTS` | `true` | Enables result archiving if supported by the current workflow |
| `EXPORT_LATEX` | `true` | Enables LaTeX export if supported |
| `EXPORT_JSON` | `true` | Enables JSON export if supported |
| `EXPORT_CSV` | `true` | Enables CSV export if supported |

### Variables often overridden dynamically

In newer runner-based setups, some variables are documented for transparency but are often assigned dynamically during execution:

- `GROUND_TRUTH_BUILD_PATH`
- `DTRACK_PROJECT_NAME`
- `DTRACK_PROJECT_VERSION`
- `DTRACK_PROJECT_UUID`
- `EVAL_ARTIFACTS_DIR`
- `TOOL_OUTPUT_DIR`
- `OUTPUT_DIR`

For this reason, the safest publication setup is:
- keep a documented template such as `.env_example`,
- store secrets only in local, ignored files,
- let the orchestration layer assign run-specific output paths where applicable.

### Minimal example `.env`

```bash
CODEBASE="/path/to/sca_tool_evaluation"
CODEBASE_BUILD_PATH="${CODEBASE}/build"
EXPERIMENT_PATH="${CODEBASE_BUILD_PATH}/experiments"

GITHUB_TOKEN="your_github_token"

SAMPLES=1000
START_DATE="2020-01-01"
END_DATE="2026-01-25"
ECOSYSTEMS="nuget maven pypi npm"
BALANCE=false
BALANCE_STRATEGY="min"

EVAL_TOOLS="snyk oss-index github trivy dtrack"

DTRACK_URL="http://your-dtrack-host:8081"
DTRACK_API_KEY="your_dtrack_api_key"
```

## Reproducibility Workflow

A typical end-to-end workflow is:

1. Generate a fixed ground-truth dataset.
2. Archive the generated CSV, SBOM, statistics, and metadata outputs.
3. Run single-tool or repeated temporal evaluation against that fixed dataset.
4. Archive the produced JSON, TXT, LaTeX, and plot artifacts.
5. Reference the exact software release and exact dataset release in publications.

## Example End-to-End Run

```bash
# 1) Generate ground truth
export GROUND_TRUTH_BUILD_PATH=./artifacts/ground-truth
export SAMPLES=1000
export ECOSYSTEMS="nuget maven pypi npm"
export START_DATE=2020-01-01
export END_DATE=2026-01-25
export BALANCE=false
poetry run python -m ground_truth_generation.build_multi_ground_truth_dataset

# 2) Evaluate one tool
poetry run python -m evaluation.evaluate \
  --ground-truth ./artifacts/ground-truth/mixed_ground_truth_dataset.csv \
  --tool oss-index

# 3) Run repeated comparison
export EVAL_TOOLS="dtrack oss-index github snyk trivy"
poetry run python -m evaluation.temporal_runner \
  --ground-truth ./artifacts/ground-truth/mixed_ground_truth_dataset.csv \
  --sbom ./artifacts/ground-truth/mixed_ground_truth_dataset.sbom.json \
  --output ./artifacts/temporal-run
```

## Running the Full Experiment

For a complete end-to-end experiment run (ground-truth generation + repeated evaluation + aggregation), use the provided shell script:

```bash
# 1. Set up a .env file at the project root (see "Minimal example .env" above)

# 2. Run the experiment
bash tools/run_experiment.sh
```

`run_experiment.sh` automates the full workflow:
- Loads configuration from `.env`
- Generates a fresh ground-truth dataset (or uses a fixed one if configured)
- Prepares a Dependency-Track project and uploads the SBOM (if `dtrack` is in `EVAL_TOOLS`)
- Runs repeated temporal evaluation across all configured tools
- Aggregates results and exports comparison summaries, plots, and LaTeX tables

The script requires the `.env` file to be present at the project root with at least `CODEBASE`, `EXPERIMENT_PATH`, `NUM_RUNS`, and `GITHUB_TOKEN` set. If `dtrack` is among the evaluated tools, `DTRACK_URL` and `DTRACK_API_KEY` are also required.

## Development

Typical development commands with Poetry:

```bash
poetry run pytest
poetry run ruff check .
poetry run ruff format .
```

A root-level `Makefile` wraps the common workflows:

```bash
make install    # poetry install
make test       # run pytest
make coverage   # pytest with coverage (XML + terminal)
make lint       # ruff check
make format     # ruff format
make sbom       # CycloneDX SBOM from poetry.lock (build/sbom/)
make sonar      # SonarQube scan (requires SONAR_URL, SONAR_TOKEN)
make clean      # remove build artifacts
```

## Release Preparation Checklist

Before publishing a release, make sure to:
- align the public README with the actually enabled adapters,
- provide a minimal reproducible example,
- include `CITATION.cff`,
- include `.zenodo.json`,
- add a project license,
- add a `.env.example` without secrets,
- verify that all command examples work in a clean Poetry environment,
- archive the exact software release and the corresponding dataset release.

## Citation

If you use this software in research, please cite:
- the archived software release,
- the corresponding ground-truth dataset release.

See:
- `CITATION.cff`
- Zenodo release metadata
- dataset DOI

## License

- **Code:** Licensed under the [Apache License, Version 2.0](LICENSE).
- **Dataset:** Ground-truth datasets generated by this framework are intended
  to be released separately (e.g. on Zenodo) under [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/).

See [`NOTICE`](NOTICE) for attribution requirements when redistributing this
software or derivative works.

## Acknowledgments

This repository was developed to support reproducible benchmarking of SCA tools against a versioned multi-ecosystem vulnerability ground truth.

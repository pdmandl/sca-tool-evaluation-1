---
title: Tool Adapters
type: architecture
module: src/evaluation/adapters
tags: [architecture, module, adapters, sca-tools]
---

# Tool Adapters

`src/evaluation/adapters/` normalizes the output of six SCA tools / advisory
sources into the single [[evaluation-core|Finding]] model. Each adapter isolates
one source's transport (REST, GraphQL, CLI subprocess) and quirks behind a
uniform contract ([[decision-0001-adapter-pattern-for-tools]]).

See also: [[overview]], [[evaluation-core]], [[glossary]].

## Base contract (`base.py`)

`VulnerabilityToolAdapter` provides:
- `name()` — tool identifier.
- `load_findings()` / `load_findings_for_component(ecosystem, component, version)`
  — return normalized `Finding[]`.
- `supports_fp_heuristic()` / `supports_security_findings()` — capability flags.
- Shared infra: per-tool **API-call logging** (`_api_call`, writes
  `<gt>_<tool>_api.log`), **CLI-call logging** (`_log_cli_call`), API-stat
  collection (`_record_api_stat`), and `iter_with_progress()` (tqdm gated by
  `EVAL_PROGRESS`).

Every adapter dedupes on `(ecosystem, component, version, canonical_id)` where
`canonical_id = cve or ghsa or osv_id`, and **requires** at least one CVE/GHSA
identifier (otherwise the finding is dropped) — this feeds the identifier-gated
matching in [[decision-0005-identifier-gated-project-centric-matching]].

## The six adapters

| Adapter | Source | Transport | Auth / input | Notes |
|---|---|---|---|---|
| `dtrack.py` `DependencyTrackAdapter` | OWASP Dependency-Track | REST | `DTRACK_URL`, `DTRACK_API_KEY`, `DTRACK_PROJECT_NAME` | Resolves project UUID, fetches `/api/v1/finding/project/{uuid}`; PURL→ecosystem. |
| `snyk.py` `SnykAdapter` | Snyk CLI | bash wrapper subprocess | `SNYK_SBOM_FILE`, `SNYK_BASH_SCRIPT` (`tools/evaluate_snyk.sh`) | Retry + timeout logic; runs `snyk sbom test --experimental --json`. |
| `github_advisory.py` `GitHubAdvisoryAdapter` | GitHub Advisory DB | GraphQL | `GITHUB_TOKEN` | Per-component `securityVulnerabilities` query; evaluates ranges → `IN_RANGE`/`OUT_OF_RANGE`/`UNDECIDABLE` (keeps IN_RANGE + UNDECIDABLE). |
| `oss_index.py` `OSSIndexAdapter` | Sonatype OSS Index | REST batch | `OSSINDEX_USERNAME`/`OSSINDEX_TOKEN` (optional) | Batches GT components (128) into `/api/v3/component-report`; honors 429 `Retry-After`. |
| `osv.py` `OSVAdapter` | OSV.dev | REST | none (public) | **Reference/validation** adapter: GT-driven; confirms each GT row exists in OSV; sets `match_type` EXACT/RANGE. |
| `trivy.py` `TrivyAdapter` | Aqua Trivy CLI | subprocess | `TRIVY_SBOM_FILE`, `TRIVY_BIN` | `trivy sbom --format json`; single attempt (no retry). |

## Two input styles

- **SBOM-driven** (Snyk, Trivy, Dependency-Track): the tool scans the
  CycloneDX SBOM produced by [[ground-truth-generation]].
- **GT-driven** (OSV, GitHub, OSS Index): the adapter iterates over the ground
  truth's `(ecosystem, component, version)` set and queries the source directly
  (a query-per-component or batched lookup).

## Registration

No dynamic discovery. `evaluate.py :: _init_adapter(tool, config)` is a manual
`if/elif` factory over the ids `dtrack | osv | github | snyk | oss-index |
trivy`, mirrored in the argparse `--tool` choices. Adding an adapter =
subclass + import + factory branch + CLI choice.

# Contributing

Thank you for your interest in contributing to the SCA Tool Evaluation Framework.

## Ways to contribute

- Report bugs or inaccurate evaluation results via GitHub Issues.
- Propose new SCA tool adapters (see `src/evaluation/adapters/`).
- Add support for a new package ecosystem (see `src/ground_truth_generation/ecosystems/`).
- Improve documentation or add test coverage.
- Share reproducible datasets or ground-truth extensions.

## Development setup

```bash
poetry install --with dev
poetry run pytest
poetry run ruff check .
```

Or using the root `Makefile`:

```bash
make install
make test
make lint
```

## Pull request process

1. Fork the repository and create a feature branch from `main`.
2. Ensure `make lint` and `make test` pass locally.
3. Add or update tests for behavioral changes.
4. Keep commits focused and descriptive.
5. Open a PR describing the change, motivation, and any reproduction steps.

---

## Adding a new tool adapter

Adapters bridge a concrete SCA tool (CLI, API, or database) to the framework's
unified `Finding` model. Use an existing adapter as a reference:

- REST API based: `src/evaluation/adapters/oss_index.py`, `github_advisory.py`
- Local CLI based: `src/evaluation/adapters/snyk.py`, `trivy.py`
- Self-hosted server: `src/evaluation/adapters/dtrack.py`

### Required changes

The following places **must** be updated for a new adapter `mytool`:

1. **`src/evaluation/adapters/mytool.py`** — create the adapter module.
   - Subclass `VulnerabilityToolAdapter` from `evaluation.adapters.base`.
   - Implement `name()` — return a stable display name (e.g. `"MyTool"`).
   - Implement `load_findings_for_component(ecosystem, component, version)` —
     return a `list[Finding]` for exactly that `(ecosystem, component, version)`.
   - Apply identifier normalization via `evaluation.core.normalization.normalize_identifier`
     and component normalization via `normalize_component`.
   - Route every outgoing HTTP call through `self._api_call(...)` so API stats and
     per-tool API logs are captured consistently.
   - Never mutate ground-truth state; return new `Finding` instances only.
   - Optionally override `supports_fp_heuristic()` if the tool's output lends
     itself to the shared FP classification.

2. **`src/evaluation/evaluate.py`** — wire the adapter into the CLI.
   - Add `from evaluation.adapters.mytool import MyToolAdapter`.
   - Extend `_init_adapter()` with an `elif tool == "mytool": return MyToolAdapter(config)`.
   - Add `"mytool"` to the `choices=[...]` list of the `--tool` argument.

3. **`src/evaluation/core/tools.py`** — register the tool's file-id.
   - Add the display-name → slug mapping to `TOOL_FILE_IDS`, e.g.
     `"MyTool": "mytool"`. This slug is used in all artifact filenames
     (`<gt>_mytool_<run_id>_tool_findings.txt`, …) and must be filesystem-safe.

4. **`.env_example`** — document the tool's configuration.
   - Add a new section with every environment variable the adapter consumes
     (API base URL, tokens, binary paths, organization IDs, etc.).
   - Mark required variables with `[REQUIRED]`.
   - Reference the adapter's identifier in the `EVAL_TOOLS` comment block.

5. **`tools/evaluate_tools.sh`** — add a pre-flight check when the tool
   requires local CLI authentication (analogous to the existing `snyk whoami`
   check for Snyk).

6. **`README.md`** — list the adapter under "Integrated Adapters" (including
   the CLI id in backticks) and, if the repository tree is referenced, add
   `mytool.py` there.

7. **`docs/README_tool_evaluation.md`** — add one row to the
   adapter table (with the CLI id and a short description).

8. **`tests/`** — add a small test.
   - At minimum, extend `tests/test_tools.py` to assert that the new tool
     is in `TOOL_FILE_IDS` and that `tool_file_id("MyTool")` returns the
     expected slug.
   - For complex adapters, add a dedicated test that mocks the API layer
     and verifies that response parsing produces the expected `Finding`s.

### Adapter contract checklist

An adapter must:

- return `Finding` objects whose `ecosystem`, `component`, and `version`
  fields are already normalized (same shape as the ground truth),
- populate at least one of `cve`, `ghsa`, `osv_id` — otherwise the finding
  cannot match anything,
- set `affected_version_range` when the source reports a range (enables
  `TP_RANGE` matching),
- raise no exceptions on empty responses — return an empty list instead,
- be idempotent: repeated calls with identical inputs must return equal
  findings (modulo `id()`).

---

## Adding a new package ecosystem

Adding support for a new ecosystem (for example `cargo`, `golang`, or
`packagist`) is a cross-cutting change because the ecosystem name is part
of the primary key used for matching. Every layer that indexes findings
by `(ecosystem, component, version)` must learn the new value.

### Required changes

For a new ecosystem `mylang`:

1. **`src/evaluation/core/ecosystems.py`** — register canonical names.
   - Add an `EcosystemMapping` entry to the `ECOSYSTEMS` dict, for example:
     ```python
     "mylang": EcosystemMapping(
         canonical="mylang",
         purl="mylang",
         osv="MyLang",        # exact OSV ecosystem spelling
         github="MYLANG",     # GitHub Security Advisory ecosystem code, or None
     ),
     ```
   - The OSV and GitHub strings **must match** the spelling used by the
     upstream APIs exactly — otherwise cross-service lookups silently drop.

2. **`src/evaluation/core/normalization.py`** — add a canonicalization branch.
   - Extend `normalize_component()` with an `elif eco == "mylang": ...` case
     implementing the ecosystem's identity rules (case sensitivity,
     separator handling, scoping, etc.).
   - Symmetry is critical: the **same** normalization must be applied on
     the ground-truth side and on every adapter's output. Never inline
     ad-hoc normalization inside an adapter.

3. **`src/ground_truth_generation/ecosystems/mylang.py`** — new collector.
   - Expose a top-level function `collect_mylang(...)` that returns the
     same row schema as the existing collectors (see `pypi.py` for the
     simplest reference).
   - Respect `MYLANG_MAX_VERSIONS_PER_PACKAGE`, `MAX_OSV_ENTRIES_PER_COMPONENT`,
     `START_DATE`, `END_DATE`, and the global `SAMPLES` limit.
   - Route OSV and network calls through `ground_truth_generation.osv_common`
     so API tracing and rate limiting stay consistent.

4. **`src/ground_truth_generation/build_multi_ground_truth_dataset.py`** —
   wire the collector in.
   - Add `from ground_truth_generation.ecosystems.mylang import collect_mylang`.
   - Add `"mylang"` to the `SUPPORTED_ECOSYSTEMS` set.
   - Extend the dispatch block in the main collection loop with an
     `elif eco == "mylang": rows = collect_mylang(...)` branch.
   - If the ecosystem has ecosystem-specific preprocessing (e.g. Maven's
     `groupId:artifactId` fixup around line 447), add the equivalent here.

5. **`.env_example`** — document the new knobs.
   - Add `MYLANG_MAX_VERSIONS_PER_PACKAGE` under section 4 (version sampling).
   - Include `mylang` in the example `ECOSYSTEMS` value in section 3.

6. **Adapters** — for every adapter in `src/evaluation/adapters/` that
   maps ecosystem names to a tool-specific ecosystem code, add the new
   mapping. Typical spots:
   - OSS Index coordinate scheme,
   - GitHub Advisory GraphQL `ecosystem:` filter,
   - Snyk / Trivy purl handling,
   - Dependency-Track project/component type.
   If an adapter does not support the new ecosystem yet, make it return an
   empty list (with a warning) rather than crashing.

7. **`src/evaluation/core/ground_truth.py`** — verify that the CSV loader
   reads the new ecosystem transparently; usually no change is needed, but
   confirm that downstream filters (e.g. ecosystem allow-lists) do not
   silently drop the new value.

8. **`README.md`** — add the ecosystem under "Supported Ecosystems" and to
   the example `ECOSYSTEMS` env value.

9. **`tests/`** — extend `tests/test_ecosystems.py` (the mapping is
   present, OSV/GitHub spellings match) and `tests/test_normalization.py`
   (canonicalization behaves as expected). Cover edge cases specific to
   the ecosystem (e.g. case-folding rules, scoped names, group/artifact
   separators).

### Ecosystem contract checklist

A new ecosystem is correctly integrated when:

- `normalize_component("mylang", x)` is idempotent and symmetric across
  ground-truth and every adapter,
- the OSV and GitHub spelling in `ECOSYSTEMS` match the upstream APIs
  exactly,
- `collect_mylang(...)` honors all ground-truth-generation env vars,
- `make test` passes and a small run
  (`ECOSYSTEMS="mylang"`, `SAMPLES=10`) produces a non-empty CSV,
- the matching semantics (TP_EXACT / TP_RANGE / FP / FN) observed for the
  new ecosystem are consistent with those of the existing ecosystems.

---

## Code of conduct

This project follows the Contributor Covenant. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

By contributing you agree that your contributions will be licensed under the
Apache License 2.0.

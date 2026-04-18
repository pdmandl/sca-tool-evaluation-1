# Contributing

Thank you for your interest in contributing to the SCA Tool Evaluation Framework.

## Ways to contribute

- Report bugs or inaccurate evaluation results via GitHub Issues.
- Propose new SCA tool adapters (see `src/evaluation/adapters/`).
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

## Adding a new tool adapter

Create a subclass of `VulnerabilityToolAdapter` in `src/evaluation/adapters/`
and register it in `src/evaluation/evaluate.py`. See existing adapters such as
`oss_index.py` or `snyk.py` for reference.

Adapters must:

- return `Finding` objects via `load_findings_for_component()`,
- apply the shared normalization utilities from `evaluation.core.normalization`,
- not mutate ground-truth state.

## Code of conduct

This project follows the Contributor Covenant. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

By contributing you agree that your contributions will be licensed under the
Apache License 2.0.

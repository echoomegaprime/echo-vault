# Contributing

Contributions are welcome through focused pull requests.

1. Open an issue describing the behavior or security invariant being changed.
2. Add or update tests before changing cryptographic, authorization, storage, or audit behavior.
3. Run `python -m pytest`, `ruff check .`, `ruff format --check .`, and `mypy`.
4. Never use production secrets or databases in tests, fixtures, screenshots, commits, or issue text.
5. Keep migrations forward-only and restore-compatible.

Changes to encryption formats, authentication canonicals, key rotation, destructive operations, or audit verification require two maintainers and a release-note security section.

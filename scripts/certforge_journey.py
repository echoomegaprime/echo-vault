#!/usr/bin/env python3
"""Read-only repository journey for the locked Certification Forge sandbox."""

from __future__ import annotations

import ast
import json
import tomllib
from pathlib import Path

REQUIRED_FILES = {
    "AGENTS.md",
    "CHANGELOG.md",
    "CLAUDE.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "SUPPORT.md",
    "Dockerfile",
    "pyproject.toml",
    ".echo/apps.json",
    ".echo/sdk.json",
    "scripts/e2e_cli.py",
}
REQUIRED_APPS = {
    "repo-steward",
    "certification-forge",
    "knowledge-forge",
    "fleet-builder",
    "release-sentinel",
    "arcanum",
    "sdk",
    "build-tracker",
}
REQUIRED_CAPABILITIES = {
    "echo.vault.secrets.put",
    "echo.vault.secrets.get",
    "echo.vault.secrets.list",
    "echo.vault.secrets.delete",
    "echo.vault.audit.verify",
    "echo.vault.admin.rekey",
}
EXCLUDED_TREE_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "site-packages",
    "venv",
}


def _load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path} must contain a JSON object")
    return value


def run() -> dict[str, object]:
    root = Path.cwd()
    missing = sorted(path for path in REQUIRED_FILES if not (root / path).is_file())
    if missing:
        raise AssertionError(f"required repository files are missing: {', '.join(missing)}")

    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    if pyproject.get("project", {}).get("name") != "echo-vault":
        raise AssertionError("pyproject project identity is not echo-vault")

    parsed_python = 0
    for path in sorted(root.rglob("*.py")):
        if EXCLUDED_TREE_PARTS.intersection(path.parts):
            continue
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        parsed_python += 1
    if parsed_python < 10:
        raise AssertionError("repository Python surface is unexpectedly small")

    apps = _load_json(root / ".echo" / "apps.json")
    app_entries = apps.get("apps")
    if apps.get("version") != 1 or not isinstance(app_entries, dict):
        raise AssertionError("GitHub App opt-in contract is malformed")
    enabled_apps = {
        key
        for key, value in app_entries.items()
        if isinstance(value, dict) and value.get("enabled") is True
    }
    if enabled_apps != REQUIRED_APPS:
        raise AssertionError("all eight governed GitHub Apps must be explicitly enabled")

    sdk = _load_json(root / ".echo" / "sdk.json")
    capabilities = sdk.get("capabilities")
    if sdk.get("version") != 1 or not isinstance(capabilities, list):
        raise AssertionError("SDK capability contract is malformed")
    if set(capabilities) != REQUIRED_CAPABILITIES:
        raise AssertionError("SDK capability contract does not match the public Vault surface")

    e2e_source = (root / "scripts" / "e2e_cli.py").read_text(encoding="utf-8")
    for required_evidence in (
        "init-put-list-get-update-get-audit-delete-list",
        "database_plaintext_absent",
        "secret_process_output_absent",
    ):
        if required_evidence not in e2e_source:
            raise AssertionError(f"real CLI E2E evidence is missing: {required_evidence}")

    return {
        "apps_enabled": len(enabled_apps),
        "capabilities_declared": len(capabilities),
        "journey": "exact-revision-repository-contract",
        "python_files_parsed": parsed_python,
        "status": "pass",
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))

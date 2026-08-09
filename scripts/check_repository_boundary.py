"""Reject tracked files that can carry live Vault material."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import PurePosixPath

BLOCKED_DIRECTORIES = {
    ".local-vault",
    "backups",
    "data",
    "exports",
    "secrets",
}
BLOCKED_BASENAMES = {
    "bootstrap-client.secret",
    "client-manifest.json",
    "clients.json",
    "keyring.json",
    "keys.json",
}
BLOCKED_EXTENSIONS = {
    ".db",
    ".jwk",
    ".jwks",
    ".kdbx",
    ".key",
    ".p12",
    ".pem",
    ".pfx",
    ".sqlite",
    ".sqlite3",
}
BLOCKED_NAME_PATTERN = re.compile(
    r"(?:credential|secret|vault)[-_].*(?:backup|export)|(?:backup|export)[-_].*(?:credential|secret|vault)"
)


def is_forbidden(path_value: str) -> bool:
    path = PurePosixPath(path_value.replace("\\", "/"))
    parts = {part.lower() for part in path.parts[:-1]}
    name = path.name.lower()
    if parts & BLOCKED_DIRECTORIES:
        return True
    if name in BLOCKED_BASENAMES:
        return True
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return True
    if path.suffix.lower() in BLOCKED_EXTENSIONS:
        return True
    if name.endswith(("-journal", "-shm", "-wal")):
        return True
    return BLOCKED_NAME_PATTERN.search(name) is not None


def tracked_files() -> list[str]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to inspect tracked files")
    result = subprocess.run(  # noqa: S603 - executable is resolved from the operator PATH
        [git, "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    return [item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def main() -> int:
    violations = sorted(path for path in tracked_files() if is_forbidden(path))
    if violations:
        print("Forbidden secret-bearing artifacts are tracked:", file=sys.stderr)
        for path in violations:
            print(path, file=sys.stderr)
        return 1
    print("Repository boundary: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

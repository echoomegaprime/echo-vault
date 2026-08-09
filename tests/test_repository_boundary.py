from scripts.check_repository_boundary import is_forbidden


def test_repository_boundary_rejects_force_added_runtime_material() -> None:
    forbidden = [
        "keys.json",
        "deploy/clients.json",
        "data/vault.db",
        "runtime/vault.db-wal",
        "runtime/vault.db-shm",
        ".local-vault/bootstrap-client.secret",
        "exports/credentials.json",
        "private.jwk",
        ".env.production",
    ]
    assert all(is_forbidden(path) for path in forbidden)


def test_repository_boundary_allows_code_and_examples() -> None:
    allowed = [
        ".env.example",
        "src/echo_vault/crypto.py",
        "docs/OPERATIONS.md",
        "tests/test_api.py",
        "SECURITY.md",
    ]
    assert not any(is_forbidden(path) for path in allowed)

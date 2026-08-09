"""Environment-backed configuration with production fail-closed validation."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    """Runtime settings. Secret values live in root-only files, not environment JSON."""

    environment: str
    data_dir: Path
    keys_file: Path
    clients_file: Path
    audit_anchor_file: Path | None = None
    host: str = "127.0.0.1"
    port: int = 8080
    max_body_bytes: int = 131_072
    timestamp_skew_seconds: int = 90
    nonce_ttl_seconds: int = 300
    rate_capacity: int = 120
    rate_refill_per_second: int = 2

    @property
    def database_path(self) -> Path:
        return self.data_dir / "vault.db"

    @property
    def audit_anchor_path(self) -> Path:
        return self.audit_anchor_file or self.data_dir / "audit.anchor"

    @classmethod
    def from_env(cls) -> Settings:
        environment = os.getenv("ECHO_VAULT_ENV", "production").strip().lower()
        if environment not in {"production", "development", "test"}:
            raise ValueError("ECHO_VAULT_ENV must be production, development, or test")
        data_dir = Path(os.getenv("ECHO_VAULT_DATA_DIR", "/var/lib/echo-vault"))
        anchor_raw = os.getenv("ECHO_VAULT_AUDIT_ANCHOR_FILE")
        return cls(
            environment=environment,
            data_dir=data_dir,
            keys_file=Path(os.getenv("ECHO_VAULT_KEYS_FILE", "/run/secrets/echo_vault_keys")),
            clients_file=Path(
                os.getenv("ECHO_VAULT_CLIENTS_FILE", "/run/secrets/echo_vault_clients")
            ),
            audit_anchor_file=Path(anchor_raw) if anchor_raw else None,
            host=os.getenv("ECHO_VAULT_HOST", "127.0.0.1"),
            port=_bounded_int("ECHO_VAULT_PORT", 8080, 1, 65_535),
            max_body_bytes=_bounded_int("ECHO_VAULT_MAX_BODY_BYTES", 131_072, 1_024, 4_194_304),
            timestamp_skew_seconds=_bounded_int("ECHO_VAULT_TIMESTAMP_SKEW_SECONDS", 90, 15, 900),
            nonce_ttl_seconds=_bounded_int("ECHO_VAULT_NONCE_TTL_SECONDS", 300, 30, 3_600),
            rate_capacity=_bounded_int("ECHO_VAULT_RATE_CAPACITY", 120, 1, 10_000),
            rate_refill_per_second=_bounded_int("ECHO_VAULT_RATE_REFILL_PER_SECOND", 2, 1, 1_000),
        )

    def validate(self) -> None:
        if self.environment == "production" and self.host in {"", "localhost"}:
            raise ValueError("production host must be explicit")
        if self.environment == "production" and os.name != "posix":
            raise ValueError(
                "production requires a POSIX permission backend; "
                "Windows is supported for development"
            )
        if self.nonce_ttl_seconds < self.timestamp_skew_seconds * 2:
            raise ValueError(
                "ECHO_VAULT_NONCE_TTL_SECONDS must be at least twice the timestamp skew"
            )
        for label, path in (("key ring", self.keys_file), ("client manifest", self.clients_file)):
            if not path.is_file():
                raise ValueError(f"{label} file is unavailable: {path}")

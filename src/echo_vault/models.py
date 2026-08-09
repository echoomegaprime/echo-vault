"""Public API models with bounded fields and explicit update semantics."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class SecretInput(BaseModel):
    secret: str = Field(min_length=1, max_length=65_536)
    username: str | None = Field(default=None, max_length=512)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, tags: list[str]) -> list[str]:
        cleaned = []
        for tag in tags:
            value = tag.strip().lower()
            if not value or len(value) > 64:
                raise ValueError("tags must contain 1 to 64 characters")
            cleaned.append(value)
        return sorted(set(cleaned))

    @model_validator(mode="after")
    def validate_payload_size(self) -> SecretInput:
        if len(json.dumps(self.metadata, separators=(",", ":")).encode()) > 32_768:
            raise ValueError("metadata exceeds 32768 encoded bytes")
        return self


class CreateSecret(SecretInput):
    pass


class UpdateSecret(SecretInput):
    expected_version: int = Field(ge=1)


class DeleteSecret(BaseModel):
    expected_version: int = Field(ge=1)


class MutationResult(BaseModel):
    namespace: str
    name: str
    version: int
    key_id: str
    updated_at: str


class SecretResult(MutationResult):
    secret: str
    username: str | None
    metadata: dict[str, Any]
    tags: list[str]


class SecretMetadata(BaseModel):
    namespace: str
    name: str
    current_version: int
    tags: list[str]
    key_id: str
    created_at: str
    updated_at: str


class AuditVerification(BaseModel):
    valid: bool
    events: int
    first_bad_event_id: int | None = None
    database_id: str | None = None
    terminal_hash: str | None = None
    anchor_signature: str | None = None

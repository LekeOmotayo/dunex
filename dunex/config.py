"""
Configuration schema and environment loader for Dunex Guardrails.
"""

from __future__ import annotations

import os
from typing import List, Optional
from pydantic import BaseModel, Field


class GuardrailsConfig(BaseModel):
    """Global configuration for Dunex inspection pipelines and server."""
    # Service identity
    service_name: str = "dunex"
    version: str = "1.0.0"
    env: str = Field(default_factory=lambda: os.getenv("DUNEX_ENV", "development"))
    host: str = Field(default_factory=lambda: os.getenv("HOST", "0.0.0.0"))
    port: int = Field(default_factory=lambda: int(os.getenv("PORT", "8000")))
    log_level: str = Field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))

    # PII settings
    enable_pii_inspection: bool = True
    enable_token_classification: bool = True
    default_masking_strategy: str = "REDACT"
    hash_salt: str = Field(default_factory=lambda: os.getenv("DUNEX_HASH_SALT", "dunex-secret-salt-2026"))

    # Prompt injection settings
    enable_injection_defense: bool = True
    injection_threshold: float = 0.65
    strict_injection_check: bool = False

    # Toxicity & safety
    enable_toxicity_inspection: bool = True
    toxicity_threshold: float = 0.50

    # Agent policy defaults
    default_max_input_length: int = 16384
    default_max_output_tokens: int = 4096

    # Audit & Storage
    audit_storage_backend: str = Field(default_factory=lambda: os.getenv("DUNEX_AUDIT_BACKEND", "memory")) # "memory", "jsonl", "dynamodb"
    audit_log_path: str = Field(default_factory=lambda: os.getenv("DUNEX_AUDIT_PATH", "audit_logs.jsonl"))
    dynamodb_table_name: str = Field(default_factory=lambda: os.getenv("DUNEX_DYNAMODB_TABLE", "dunex_audit_logs"))
    dynamodb_region: str = Field(default_factory=lambda: os.getenv("AWS_REGION", "us-east-1"))
    audit_ttl_days: int = 90

    # API Keys / Auth
    api_tokens: List[str] = Field(
        default_factory=lambda: [
            t.strip() for t in os.getenv("DUNEX_API_TOKENS", "dunex-dev-token").split(",") if t.strip()
        ]
    )

    @classmethod
    def load(cls) -> "GuardrailsConfig":
        """Instantiate config from environment."""
        return cls()

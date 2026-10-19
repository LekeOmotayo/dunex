"""
Data models, enums, and schemas for Dunex LLM Guardrails & Data Leakage Prevention.
Fully typed with Pydantic v2.
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PIIType(str, Enum):
    """Categorization of Personally Identifiable Information and Secrets."""
    SSN = "SSN"
    API_KEY = "API_KEY"
    CREDIT_CARD = "CREDIT_CARD"
    EMAIL = "EMAIL"
    PHONE_NUMBER = "PHONE_NUMBER"
    IP_ADDRESS = "IP_ADDRESS"
    BANK_ROUTING = "BANK_ROUTING"
    IBAN = "IBAN"
    PASSWORD_CREDENTIAL = "PASSWORD_CREDENTIAL"
    GENERIC_SECRET = "GENERIC_SECRET"


class MaskingStrategy(str, Enum):
    """Strategy for masking discovered PII."""
    REDACT = "REDACT"             # e.g., [REDACTED_SSN]
    HASH = "HASH"                 # e.g., [SHA256:8f4b...]
    MASK_PARTIAL = "MASK_PARTIAL" # e.g., ***-**-1234
    TOKENIZE = "TOKENIZE"         # e.g., [TOKEN_SSN_98214]


class InjectionType(str, Enum):
    """Classification of Prompt Injection vectors."""
    SYSTEM_PROMPT_OVERRIDE = "SYSTEM_PROMPT_OVERRIDE"
    JAILBREAK = "JAILBREAK"
    ROLE_REVERSAL = "ROLE_REVERSAL"
    DELIMITER_ESCAPE = "DELIMITER_ESCAPE"
    INDIRECT_INJECTION = "INDIRECT_INJECTION"
    UNRESTRICTED_MODE = "UNRESTRICTED_MODE"


class GuardrailVerdict(str, Enum):
    """Overall outcome of guardrail inspection."""
    ALLOW = "ALLOW"
    MASKED = "MASKED"
    WARN = "WARN"
    BLOCKED = "BLOCKED"


class PIIDetection(BaseModel):
    """A detected PII or credential token within analyzed text."""
    entity_type: PIIType
    raw_text: str
    masked_text: str
    start: int
    end: int
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    detector: str = "regex" # "regex" or "token_classifier"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class InjectionDetection(BaseModel):
    """A detected prompt injection vector."""
    attack_type: InjectionType
    matched_pattern: str
    risk_score: float = Field(ge=0.0, le=1.0)
    severity: str = "HIGH" # LOW, MEDIUM, HIGH, CRITICAL
    explanation: str


class ToxicityScore(BaseModel):
    """Toxicity and safety category scoring."""
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    flagged: bool = False
    categories: Dict[str, float] = Field(default_factory=dict)
    matched_terms: List[str] = Field(default_factory=list)


class AgentPolicy(BaseModel):
    """Granular per-agent security boundaries and permissions."""
    agent_id: str
    tenant_id: str = "default"
    allowed_topics: List[str] = Field(default_factory=list)
    blocked_topics: List[str] = Field(default_factory=list)
    allowed_tools: List[str] = Field(default_factory=list)
    max_input_length: int = 16384
    max_output_tokens: int = 4096
    pii_masking_enabled: bool = True
    default_masking_strategy: MaskingStrategy = MaskingStrategy.REDACT
    allowed_pii_types: List[PIIType] = Field(default_factory=list) # Types allowed through
    injection_threshold: float = Field(default=0.65, ge=0.0, le=1.0)
    toxicity_threshold: float = Field(default=0.50, ge=0.0, le=1.0)
    block_on_injection: bool = True
    block_on_toxicity: bool = True
    strict_mode: bool = False


class InspectionRequest(BaseModel):
    """Payload to inspect text against guardrail rules."""
    text: str
    agent_id: str = "default-agent"
    tenant_id: str = "default-tenant"
    direction: str = "input" # "input" or "output"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class InspectionResult(BaseModel):
    """Consolidated guardrail analysis result."""
    verdict: GuardrailVerdict
    risk_score: float = Field(ge=0.0, le=1.0)
    original_text: str
    sanitized_text: str
    pii_detections: List[PIIDetection] = Field(default_factory=list)
    injection_detections: List[InjectionDetection] = Field(default_factory=list)
    toxicity: ToxicityScore = Field(default_factory=ToxicityScore)
    violations: List[str] = Field(default_factory=list)
    execution_time_ms: float = 0.0
    request_id: str = Field(default_factory=lambda: f"req_{uuid.uuid4().hex[:12]}")


class DynamoDBAuditItem(BaseModel):
    """
    Immutable audit-trail record structured for direct NoSQL / DynamoDB ingestion.
    Primary Key: PK = TENANT#{tenant_id}#AGENT#{agent_id}
    Sort Key:    SK = TS#{epoch_ms}#REQ#{request_id}
    GSI1 PK:     GSI1PK = TENANT#{tenant_id}#VERDICT#{verdict}
    GSI1 SK:     GSI1SK = TS#{epoch_ms}
    """
    pk: str = Field(..., description="Partition key: TENANT#{tenant_id}#AGENT#{agent_id}")
    sk: str = Field(..., description="Sort key: TS#{timestamp_ms}#REQ#{request_id}")
    gsi1pk: str = Field(..., description="GSI1 partition key for verdict queries")
    gsi1sk: str = Field(..., description="GSI1 sort key for chronological indexing")
    
    request_id: str
    agent_id: str
    tenant_id: str
    timestamp_iso: str
    timestamp_epoch: int
    ttl: int = Field(..., description="DynamoDB TTL attribute for auto-expiry (epoch seconds)")
    
    direction: str # input | output
    verdict: GuardrailVerdict
    risk_score: float
    violations: List[str]
    pii_count: int
    injection_count: int
    toxicity_score: float
    
    masked_pii_types: List[str]
    sanitized_preview: str # Truncated preview to prevent sensitive data logging
    execution_time_ms: float
    metadata: Dict[str, Any] = Field(default_factory=dict)

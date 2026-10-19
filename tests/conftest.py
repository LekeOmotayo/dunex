"""
Pytest fixtures for Dunex LLM Guardrails test suite.
"""

import pytest
from dunex.config import GuardrailsConfig
from dunex.models import AgentPolicy, MaskingStrategy, PIIType
from dunex.permissions.policy import AgentPolicyRegistry
from dunex.pipeline import GuardrailPipeline
from dunex.audit.logger import AuditLogger


@pytest.fixture
def config() -> GuardrailsConfig:
    return GuardrailsConfig(
        service_name="dunex-test",
        env="testing",
        enable_pii_inspection=True,
        enable_token_classification=True,
        enable_injection_defense=True,
        enable_toxicity_inspection=True,
        injection_threshold=0.65,
        toxicity_threshold=0.50,
        hash_salt="test-salt-1234",
    )


@pytest.fixture
def policy_registry() -> AgentPolicyRegistry:
    registry = AgentPolicyRegistry()
    registry.register(
        AgentPolicy(
            agent_id="test-finance-agent",
            tenant_id="tenant-alpha",
            allowed_topics=["markets", "stocks", "accounting"],
            blocked_topics=["insider_trading", "weapons", "classified"],
            allowed_tools=["calculator", "stock_api"],
            max_input_length=5000,
            pii_masking_enabled=True,
            default_masking_strategy=MaskingStrategy.REDACT,
            injection_threshold=0.65,
            toxicity_threshold=0.50,
            block_on_injection=True,
            block_on_toxicity=True,
            strict_mode=False,
        )
    )
    return registry


@pytest.fixture
def audit_logger() -> AuditLogger:
    return AuditLogger(buffer_size=100)


@pytest.fixture
def pipeline(config, policy_registry, audit_logger) -> GuardrailPipeline:
    return GuardrailPipeline(
        config=config,
        policy_registry=policy_registry,
        audit_logger=audit_logger,
    )

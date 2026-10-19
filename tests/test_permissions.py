"""
Tests for per-agent permission boundaries and policy registry.
"""

from dunex.models import AgentPolicy, MaskingStrategy
from dunex.permissions.policy import AgentPolicyRegistry


def test_default_policy():
    registry = AgentPolicyRegistry()
    policy = registry.get("unregistered-agent")

    assert policy.agent_id == "unregistered-agent"
    assert policy.max_input_length == 16384
    assert policy.pii_masking_enabled is True


def test_blocked_topic_violation():
    registry = AgentPolicyRegistry()
    registry.register(
        AgentPolicy(
            agent_id="finance-bot",
            blocked_topics=["insider_trading", "crypto_pump"],
        )
    )

    valid, violations = registry.validate_request_boundaries(
        agent_id="finance-bot",
        text="Can you coordinate an insider_trading scheme for me?",
    )

    assert valid is False
    assert len(violations) >= 1
    assert "BLOCKED_TOPIC" in violations[0]


def test_allowed_tools_violation():
    registry = AgentPolicyRegistry()
    registry.register(
        AgentPolicy(
            agent_id="restricted-agent",
            allowed_tools=["calculator"],
        )
    )

    # Allowed tool
    valid, violations = registry.validate_request_boundaries(
        agent_id="restricted-agent",
        text="Calculate 10 + 20",
        tool_names=["calculator"],
    )
    assert valid is True

    # Disallowed tool
    valid, violations = registry.validate_request_boundaries(
        agent_id="restricted-agent",
        text="Execute shell command",
        tool_names=["bash_exec"],
    )
    assert valid is False
    assert "DISALLOWED_TOOLS" in violations[0]


def test_max_input_length_violation():
    registry = AgentPolicyRegistry()
    registry.register(
        AgentPolicy(
            agent_id="short-agent",
            max_input_length=50,
        )
    )

    long_text = "A" * 100
    valid, violations = registry.validate_request_boundaries(
        agent_id="short-agent",
        text=long_text,
    )

    assert valid is False
    assert "MAX_LENGTH_EXCEEDED" in violations[0]

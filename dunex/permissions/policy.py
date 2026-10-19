"""
Granular per-agent permission boundaries and policy enforcement engine.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from dunex.models import AgentPolicy, GuardrailVerdict, PIIType, MaskingStrategy


class PolicyViolation(Exception):
    """Raised when an agent violates configured permission boundaries."""
    def __init__(self, message: str, violation_code: str) -> None:
        super().__init__(message)
        self.violation_code = violation_code


class AgentPolicyRegistry:
    """Manages and enforces policy profiles for autonomous AI agents."""

    def __init__(self) -> None:
        self._policies: Dict[str, AgentPolicy] = {}
        # Default fallback policy
        self._default_policy = AgentPolicy(
            agent_id="default",
            tenant_id="default",
            allowed_topics=[],
            blocked_topics=["classified", "internal_credentials"],
            allowed_tools=["calculator", "web_search", "document_retrieval"],
            max_input_length=16384,
            max_output_tokens=4096,
            pii_masking_enabled=True,
            default_masking_strategy=MaskingStrategy.REDACT,
            injection_threshold=0.65,
            toxicity_threshold=0.50,
            block_on_injection=True,
            block_on_toxicity=True,
            strict_mode=False,
        )

    def register(self, policy: AgentPolicy) -> None:
        """Register or update an agent policy."""
        self._policies[policy.agent_id] = policy

    def get(self, agent_id: str) -> AgentPolicy:
        """Retrieve policy for an agent, returning default if not explicitly registered."""
        return self._policies.get(agent_id, self._default_policy.model_copy(update={"agent_id": agent_id}))

    def list_policies(self) -> List[AgentPolicy]:
        """List all active agent policies."""
        return list(self._policies.values())

    def validate_request_boundaries(
        self,
        agent_id: str,
        text: str,
        tool_names: Optional[List[str]] = None,
    ) -> Tuple[bool, List[str]]:
        """
        Validate whether a request satisfies the agent's permission boundaries.
        Returns (is_valid, list_of_violations).
        """
        policy = self.get(agent_id)
        violations: List[str] = []

        # 1. Max input length check
        if len(text) > policy.max_input_length:
            violations.append(
                f"MAX_LENGTH_EXCEEDED: Text length ({len(text)}) exceeds policy limit ({policy.max_input_length})"
            )

        # 2. Blocked topics evaluation
        text_lower = text.lower()
        for topic in policy.blocked_topics:
            pattern = re.compile(rf"\b{re.escape(topic.lower())}\b")
            if pattern.search(text_lower):
                violations.append(f"BLOCKED_TOPIC: Content references prohibited topic '{topic}'")

        # 3. Strict mode allowed topics check
        if policy.strict_mode and policy.allowed_topics:
            matched_any = any(
                re.search(rf"\b{re.escape(top.lower())}\b", text_lower)
                for top in policy.allowed_topics
            )
            if not matched_any:
                violations.append(
                    f"STRICT_TOPIC_REQUIRED: Content did not match any allowed topic in {policy.allowed_topics}"
                )

        # 4. Tool boundary permissions
        if tool_names and policy.allowed_tools:
            disallowed = [t for t in tool_names if t not in policy.allowed_tools]
            if disallowed:
                violations.append(
                    f"DISALLOWED_TOOLS: Agent requested unauthorized tools: {disallowed}"
                )

        return (len(violations) == 0), violations

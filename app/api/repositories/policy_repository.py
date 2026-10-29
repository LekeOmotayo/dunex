"""
Policy Repository for Dunex Agent Permission Policies.
"""

from typing import Dict, Optional, List
from dunex.models import AgentPolicy
from dunex.permissions.policy import AgentPolicyRegistry


class PolicyRepository:
    """Provides abstracted data access for agent security policies."""

    def __init__(self, registry: Optional[AgentPolicyRegistry] = None):
        self.registry = registry or AgentPolicyRegistry()

    def get_policy(self, agent_id: str) -> Optional[AgentPolicy]:
        return self.registry.get(agent_id)

    def save_policy(self, policy: AgentPolicy) -> None:
        self.registry.register(policy)

    def list_policies(self) -> Dict[str, AgentPolicy]:
        return self.registry._policies

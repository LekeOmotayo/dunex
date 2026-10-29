"""
FastAPI Router for Agent Security Policy endpoints.
"""

from typing import List
from fastapi import APIRouter
from dunex.models import AgentPolicy
from app.api.controllers.guardrail_controller import get_guardrail_service

router = APIRouter(prefix="/v1/agents", tags=["Agent Permissions"])


@router.get(
    "",
    response_model=List[AgentPolicy],
    summary="List all registered agent permission policies",
)
async def list_agent_policies():
    service = get_guardrail_service()
    return service.policy_repo.registry.list_policies()


@router.get(
    "/{agent_id}/policy",
    response_model=AgentPolicy,
    summary="Get policy for a specific agent",
)
async def get_agent_policy(agent_id: str):
    service = get_guardrail_service()
    return service.policy_repo.get_policy(agent_id)


@router.put(
    "/{agent_id}/policy",
    response_model=AgentPolicy,
    summary="Create or update policy for an agent",
)
async def update_agent_policy(agent_id: str, policy: AgentPolicy):
    policy.agent_id = agent_id
    service = get_guardrail_service()
    service.policy_repo.save_policy(policy)
    return policy

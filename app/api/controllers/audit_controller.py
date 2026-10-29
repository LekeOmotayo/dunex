"""
FastAPI Router for Audit Log and Compliance endpoints.
"""

from typing import Optional
from fastapi import APIRouter
from dunex.models import GuardrailVerdict
from app.api.controllers.guardrail_controller import get_guardrail_service

router = APIRouter(prefix="/v1/audit", tags=["Audit & Compliance"])


@router.get(
    "/logs",
    summary="Query immutable DynamoDB-formatted audit records",
)
async def query_audit_logs(
    limit: int = 50,
    agent_id: Optional[str] = None,
    verdict: Optional[GuardrailVerdict] = None,
):
    service = get_guardrail_service()
    items = service.audit_repo.logger.get_recent(limit=limit, agent_id=agent_id, verdict=verdict)
    return [item.model_dump() for item in items]


@router.get(
    "/summary",
    summary="Get aggregate telemetry and compliance summary",
)
async def get_audit_summary():
    service = get_guardrail_service()
    return service.audit_repo.logger.get_summary()

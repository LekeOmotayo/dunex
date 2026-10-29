"""
Guardrail Service coordinating the inspection pipeline and policy validation.
"""

from typing import Dict, Any, Optional
from dunex.pipeline import GuardrailPipeline
from dunex.config import GuardrailsConfig
from dunex.models import InspectionRequest, InspectionResult
from app.api.repositories.policy_repository import PolicyRepository
from app.api.repositories.audit_repository import AuditRepository


class GuardrailService:
    """Service layer orchestrating multimodal guardrail inspections."""

    def __init__(
        self,
        config: Optional[GuardrailsConfig] = None,
        policy_repo: Optional[PolicyRepository] = None,
        audit_repo: Optional[AuditRepository] = None,
    ):
        self.config = config or GuardrailsConfig.load()
        self.pipeline = GuardrailPipeline(config=self.config)
        self.policy_repo = policy_repo or PolicyRepository(self.pipeline.policies)
        self.audit_repo = audit_repo or AuditRepository(self.pipeline.audit)

    def inspect_inbound(self, req: InspectionRequest) -> InspectionResult:
        """Inspects and sanitizes inbound user prompts."""
        return self.pipeline.inspect(
            text=req.text,
            agent_id=req.agent_id,
            tenant_id=req.tenant_id,
            direction="input",
            metadata=req.metadata,
        )

    def inspect_outbound(self, req: InspectionRequest) -> InspectionResult:
        """Inspects and redacts sensitive data in outbound LLM generations."""
        return self.pipeline.inspect(
            text=req.text,
            agent_id=req.agent_id,
            tenant_id=req.tenant_id,
            direction="output",
            metadata=req.metadata,
        )

    def get_audit_trail(self, limit: int = 50) -> list:
        return self.audit_repo.get_recent_logs(limit=limit)

"""
DynamoDB item serializer and single-table schema builder for immutable audit trails.
"""

from __future__ import annotations

import datetime
import time
from typing import Any, Dict, List, Optional
from dunex.models import DynamoDBAuditItem, GuardrailVerdict, InspectionResult


def build_dynamodb_audit_item(
    result: InspectionResult,
    agent_id: str,
    tenant_id: str,
    direction: str = "input",
    ttl_days: int = 90,
    metadata: Optional[Dict[str, Any]] = None,
) -> DynamoDBAuditItem:
    """
    Format an inspection result into an immutable DynamoDB single-table item.
    PK: TENANT#{tenant_id}#AGENT#{agent_id}
    SK: TS#{timestamp_ms}#REQ#{request_id}
    GSI1PK: TENANT#{tenant_id}#VERDICT#{verdict}
    GSI1SK: TS#{timestamp_ms}
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    now_epoch_ms = int(now.timestamp() * 1000)
    now_epoch_sec = int(now.timestamp())
    ttl_epoch_sec = now_epoch_sec + (ttl_days * 86400)

    # Truncate sanitized preview to 256 chars to prevent storing huge logs
    preview = result.sanitized_text[:256] + ("..." if len(result.sanitized_text) > 256 else "")

    masked_types = list({d.entity_type.value for d in result.pii_detections})

    return DynamoDBAuditItem(
        pk=f"TENANT#{tenant_id}#AGENT#{agent_id}",
        sk=f"TS#{now_epoch_ms}#REQ#{result.request_id}",
        gsi1pk=f"TENANT#{tenant_id}#VERDICT#{result.verdict.value}",
        gsi1sk=f"TS#{now_epoch_ms}",
        request_id=result.request_id,
        agent_id=agent_id,
        tenant_id=tenant_id,
        timestamp_iso=now.isoformat(),
        timestamp_epoch=now_epoch_ms,
        ttl=ttl_epoch_sec,
        direction=direction,
        verdict=result.verdict,
        risk_score=result.risk_score,
        violations=result.violations,
        pii_count=len(result.pii_detections),
        injection_count=len(result.injection_detections),
        toxicity_score=result.toxicity.score,
        masked_pii_types=masked_types,
        sanitized_preview=preview,
        execution_time_ms=result.execution_time_ms,
        metadata=metadata or {},
    )


def to_dynamodb_attribute_map(item: DynamoDBAuditItem) -> Dict[str, Dict[str, Any]]:
    """Convert DynamoDBAuditItem to native low-level DynamoDB AttributeValue format."""
    return {
        "PK": {"S": item.pk},
        "SK": {"S": item.sk},
        "GSI1PK": {"S": item.gsi1pk},
        "GSI1SK": {"S": item.gsi1sk},
        "RequestId": {"S": item.request_id},
        "AgentId": {"S": item.agent_id},
        "TenantId": {"S": item.tenant_id},
        "TimestampISO": {"S": item.timestamp_iso},
        "TimestampEpoch": {"N": str(item.timestamp_epoch)},
        "TTL": {"N": str(item.ttl)},
        "Direction": {"S": item.direction},
        "Verdict": {"S": item.verdict.value},
        "RiskScore": {"N": str(item.risk_score)},
        "Violations": {"SS": item.violations if item.violations else ["NONE"]},
        "PIICount": {"N": str(item.pii_count)},
        "InjectionCount": {"N": str(item.injection_count)},
        "ToxicityScore": {"N": str(item.toxicity_score)},
        "MaskedPIITypes": {"SS": item.masked_pii_types if item.masked_pii_types else ["NONE"]},
        "SanitizedPreview": {"S": item.sanitized_preview},
        "ExecutionTimeMs": {"N": str(item.execution_time_ms)},
    }

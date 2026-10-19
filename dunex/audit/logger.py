"""
Immutable audit-trail logger supporting in-memory buffers, JSONL files, and DynamoDB.
"""

from __future__ import annotations

import collections
import json
import os
from typing import Any, Dict, List, Optional
from dunex.models import DynamoDBAuditItem, GuardrailVerdict, InspectionResult
from dunex.audit.dynamodb import build_dynamodb_audit_item, to_dynamodb_attribute_map


class AuditLogger:
    """Immutable audit-trail logger for security compliance and telemetry."""

    def __init__(
        self,
        buffer_size: int = 1000,
        jsonl_path: Optional[str] = None,
        dynamodb_table: Optional[str] = None,
        aws_region: str = "us-east-1",
        ttl_days: int = 90,
    ) -> None:
        self.buffer: collections.deque[DynamoDBAuditItem] = collections.deque(maxlen=buffer_size)
        self.jsonl_path = jsonl_path
        self.dynamodb_table = dynamodb_table
        self.aws_region = aws_region
        self.ttl_days = ttl_days
        self._dynamodb_client = None

        # Lazy init boto3 if configured
        if self.dynamodb_table and os.getenv("AWS_ACCESS_KEY_ID"):
            try:
                import boto3 # type: ignore
                self._dynamodb_client = boto3.client("dynamodb", region_name=self.aws_region)
            except Exception:
                self._dynamodb_client = None

    def log(
        self,
        result: InspectionResult,
        agent_id: str = "default",
        tenant_id: str = "default",
        direction: str = "input",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> DynamoDBAuditItem:
        """Record an immutable audit item across memory, file, and NoSQL stores."""
        item = build_dynamodb_audit_item(
            result=result,
            agent_id=agent_id,
            tenant_id=tenant_id,
            direction=direction,
            ttl_days=self.ttl_days,
            metadata=metadata,
        )

        # 1. Ring buffer
        self.buffer.append(item)

        # 2. Append to JSONLines file if enabled
        if self.jsonl_path:
            try:
                with open(self.jsonl_path, "a", encoding="utf-8") as f:
                    f.write(item.model_dump_json() + "\n")
            except Exception:
                pass # Non-blocking on disk errors

        # 3. Write to AWS DynamoDB if client is active
        if self._dynamodb_client and self.dynamodb_table:
            try:
                attr_map = to_dynamodb_attribute_map(item)
                self._dynamodb_client.put_item(
                    TableName=self.dynamodb_table,
                    Item=attr_map,
                )
            except Exception:
                pass # Fail-safe, do not crash pipeline on remote DB timeout

        return item

    def get_recent(
        self,
        limit: int = 50,
        agent_id: Optional[str] = None,
        verdict: Optional[GuardrailVerdict] = None,
    ) -> List[DynamoDBAuditItem]:
        """Query recent audit items from the memory ring buffer."""
        items = list(self.buffer)[::-1] # Newest first

        if agent_id:
            items = [i for i in items if i.agent_id == agent_id]
        if verdict:
            items = [i for i in items if i.verdict == verdict]

        return items[:limit]

    def get_summary(self) -> Dict[str, Any]:
        """Calculate aggregate telemetry metrics from recorded logs."""
        total = len(self.buffer)
        if total == 0:
            return {
                "total_inspections": 0,
                "blocked_count": 0,
                "masked_count": 0,
                "allowed_count": 0,
                "pii_detected_total": 0,
                "injection_detected_total": 0,
                "average_latency_ms": 0.0,
            }

        blocked = sum(1 for i in self.buffer if i.verdict == GuardrailVerdict.BLOCKED)
        masked = sum(1 for i in self.buffer if i.verdict == GuardrailVerdict.MASKED)
        allowed = sum(1 for i in self.buffer if i.verdict == GuardrailVerdict.ALLOW)
        pii_total = sum(i.pii_count for i in self.buffer)
        inj_total = sum(i.injection_count for i in self.buffer)
        avg_latency = sum(i.execution_time_ms for i in self.buffer) / total

        return {
            "total_inspections": total,
            "blocked_count": blocked,
            "masked_count": masked,
            "allowed_count": allowed,
            "pii_detected_total": pii_total,
            "injection_detected_total": inj_total,
            "average_latency_ms": round(avg_latency, 2),
        }

"""
Tests for immutable DynamoDB audit trail items and logger.
"""

from dunex.audit.dynamodb import build_dynamodb_audit_item, to_dynamodb_attribute_map
from dunex.audit.logger import AuditLogger
from dunex.models import GuardrailVerdict, InspectionResult, PIIDetection, PIIType


def test_build_dynamodb_audit_item():
    result = InspectionResult(
        verdict=GuardrailVerdict.MASKED,
        risk_score=0.4,
        original_text="SSN 452-82-9182",
        sanitized_text="SSN [REDACTED_SSN]",
        pii_detections=[
            PIIDetection(
                entity_type=PIIType.SSN,
                raw_text="452-82-9182",
                masked_text="[REDACTED_SSN]",
                start=4,
                end=15,
            )
        ],
        violations=[],
        execution_time_ms=1.2,
    )

    item = build_dynamodb_audit_item(
        result=result,
        agent_id="test-agent",
        tenant_id="tenant-1",
        direction="input",
        ttl_days=30,
    )

    assert item.pk == "TENANT#tenant-1#AGENT#test-agent"
    assert item.sk.startswith("TS#") and f"#REQ#{result.request_id}" in item.sk
    assert item.gsi1pk == "TENANT#tenant-1#VERDICT#MASKED"
    assert item.gsi1sk.startswith("TS#")
    assert item.verdict == GuardrailVerdict.MASKED
    assert item.pii_count == 1
    assert "SSN" in item.masked_pii_types
    assert item.ttl > item.timestamp_epoch // 1000


def test_to_dynamodb_attribute_map():
    result = InspectionResult(
        verdict=GuardrailVerdict.ALLOW,
        risk_score=0.0,
        original_text="Hello",
        sanitized_text="Hello",
        execution_time_ms=0.5,
    )
    item = build_dynamodb_audit_item(result, "agent-1", "tenant-1")
    attr_map = to_dynamodb_attribute_map(item)

    assert "PK" in attr_map and "S" in attr_map["PK"]
    assert "SK" in attr_map and "S" in attr_map["SK"]
    assert "GSI1PK" in attr_map
    assert "ExecutionTimeMs" in attr_map and "N" in attr_map["ExecutionTimeMs"]


def test_audit_logger_ring_buffer():
    logger = AuditLogger(buffer_size=5)
    for i in range(10):
        res = InspectionResult(
            verdict=GuardrailVerdict.ALLOW if i % 2 == 0 else GuardrailVerdict.BLOCKED,
            risk_score=0.0 if i % 2 == 0 else 0.9,
            original_text=f"req-{i}",
            sanitized_text=f"req-{i}",
            execution_time_ms=1.0,
        )
        logger.log(res, agent_id=f"agent-{i}")

    # Maximum 5 stored in ring buffer
    assert len(logger.buffer) == 5

    summary = logger.get_summary()
    assert summary["total_inspections"] == 5
    assert summary["blocked_count"] > 0

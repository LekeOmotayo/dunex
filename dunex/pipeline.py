"""
Central Guardrail Pipeline Orchestrator.
Combines PII scanning, token classification, prompt injection defense, toxicity filtering,
agent permission verification, and audit logging into a unified high-throughput pipeline.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from dunex.config import GuardrailsConfig
from dunex.models import (
    AgentPolicy,
    GuardrailVerdict,
    InspectionResult,
    MaskingStrategy,
    PIIDetection,
)
from dunex.pii.maskers import PIIMasker
from dunex.pii.scanner import RegexPIIScanner
from dunex.pii.classifier import LocalTokenClassifier
from dunex.injection.detector import PromptInjectionDetector
from dunex.toxicity.evaluator import ToxicityEvaluator
from dunex.permissions.policy import AgentPolicyRegistry
from dunex.audit.logger import AuditLogger


class GuardrailPipeline:
    """High-throughput multi-layered LLM guardrail inspection pipeline."""

    def __init__(
        self,
        config: Optional[GuardrailsConfig] = None,
        policy_registry: Optional[AgentPolicyRegistry] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        self.config = config or GuardrailsConfig.load()
        self.policies = policy_registry or AgentPolicyRegistry()
        self.audit = audit_logger or AuditLogger(
            buffer_size=1000,
            jsonl_path=self.config.audit_log_path if self.config.audit_storage_backend == "jsonl" else None,
            dynamodb_table=self.config.dynamodb_table_name if self.config.audit_storage_backend == "dynamodb" else None,
            aws_region=self.config.dynamodb_region,
            ttl_days=self.config.audit_ttl_days,
        )

        # Core inspection components
        self.masker = PIIMasker(salt=self.config.hash_salt)
        self.pii_scanner = RegexPIIScanner(masker=self.masker)
        self.token_classifier = LocalTokenClassifier(masker=self.masker)
        self.injection_detector = PromptInjectionDetector(
            sensitivity_threshold=self.config.injection_threshold
        )
        self.toxicity_evaluator = ToxicityEvaluator(
            default_threshold=self.config.toxicity_threshold
        )

    def inspect(
        self,
        text: str,
        agent_id: str = "default",
        tenant_id: str = "default",
        direction: str = "input",
        tool_names: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> InspectionResult:
        """
        Execute multi-layered inspection on text (input or output).
        Enforces permissions, sanitizes PII, detects injections, assesses toxicity,
        and records an immutable audit log.
        """
        start_time = time.perf_counter()
        policy = self.policies.get(agent_id)
        violations: List[str] = []
        is_blocked = False

        # ── 1. Permission Boundary Validation ─────────────────────────────────
        valid_bounds, bound_violations = self.policies.validate_request_boundaries(
            agent_id=agent_id,
            text=text,
            tool_names=tool_names,
        )
        if not valid_bounds:
            violations.extend(bound_violations)
            is_blocked = True

        # ── 2. Prompt Injection Defense (primarily on inbound prompts) ─────────
        injection_detections = []
        injection_risk = 0.0
        if self.config.enable_injection_defense and direction == "input":
            injection_detections, injection_risk = self.injection_detector.scan(text)
            if injection_risk >= policy.injection_threshold:
                violations.append(
                    f"PROMPT_INJECTION_DETECTED: Risk score {injection_risk:.2f} exceeds threshold {policy.injection_threshold:.2f}"
                )
                if policy.block_on_injection:
                    is_blocked = True

        # ── 3. Toxicity & Harm Vector Assessment ──────────────────────────────
        toxicity_score = self.toxicity_evaluator.evaluate(
            text, threshold=policy.toxicity_threshold
        )
        if self.config.enable_toxicity_inspection and toxicity_score.flagged:
            violations.append(
                f"TOXICITY_FLAGGED: Toxicity score {toxicity_score.score:.2f} exceeds threshold {policy.toxicity_threshold:.2f}"
            )
            if policy.block_on_toxicity:
                is_blocked = True

        # ── 4. PII & Data Leakage Inspection + Sanitization ───────────────────
        sanitized_text = text
        pii_detections: List[PIIDetection] = []

        if self.config.enable_pii_inspection and policy.pii_masking_enabled:
            # Stage A: Regex Scanner
            sanitized_text, regex_pii = self.pii_scanner.sanitize(
                text,
                strategy=policy.default_masking_strategy,
                allowed_types=policy.allowed_pii_types,
            )
            pii_detections.extend(regex_pii)

            # Stage B: Token Classifier (on remaining text for high-entropy secrets)
            if self.config.enable_token_classification:
                classifier_pii = self.token_classifier.classify(
                    sanitized_text,
                    existing_spans=regex_pii,
                    strategy=policy.default_masking_strategy,
                )
                if classifier_pii:
                    pii_detections.extend(classifier_pii)
                    # Apply classifier sanitizations right to left
                    result_chars = list(sanitized_text)
                    for det in sorted(classifier_pii, key=lambda d: d.start, reverse=True):
                        result_chars[det.start : det.end] = list(det.masked_text)
                    sanitized_text = "".join(result_chars)

        # ── 5. Verdict Computation ────────────────────────────────────────────
        overall_risk = max(injection_risk, toxicity_score.score)
        if pii_detections:
            overall_risk = max(overall_risk, 0.4)

        if is_blocked:
            verdict = GuardrailVerdict.BLOCKED
            # Blocked requests return safe error message rather than original text
            sanitized_text = "[REQUEST_BLOCKED_BY_GUARDRAILS: Policy or safety boundary violation]"
        elif pii_detections:
            verdict = GuardrailVerdict.MASKED
        elif violations:
            verdict = GuardrailVerdict.WARN
        else:
            verdict = GuardrailVerdict.ALLOW

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        result = InspectionResult(
            verdict=verdict,
            risk_score=round(overall_risk, 3),
            original_text=text,
            sanitized_text=sanitized_text,
            pii_detections=pii_detections,
            injection_detections=injection_detections,
            toxicity=toxicity_score,
            violations=violations,
            execution_time_ms=elapsed_ms,
        )

        # ── 6. Immutable Audit Log ────────────────────────────────────────────
        self.audit.log(
            result=result,
            agent_id=agent_id,
            tenant_id=tenant_id,
            direction=direction,
            metadata=metadata,
        )

        return result

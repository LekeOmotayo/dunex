"""
Dunex — High-Throughput LLM Guardrails & Data Leakage Prevention Engine.
Provides multi-layered PII masking, active prompt-injection defense,
per-agent permission boundaries, and DynamoDB-ready audit logging.
"""

from dunex.models import (
    AgentPolicy,
    DynamoDBAuditItem,
    GuardrailVerdict,
    InjectionDetection,
    InjectionType,
    InspectionRequest,
    InspectionResult,
    MaskingStrategy,
    PIIDetection,
    PIIType,
    ToxicityScore,
)
from dunex.config import GuardrailsConfig
from dunex.pipeline import GuardrailPipeline
from dunex.middleware import GuardrailsMiddleware
from dunex.permissions.policy import AgentPolicyRegistry, PolicyViolation
from dunex.audit.logger import AuditLogger
from dunex.pii.maskers import PIIMasker
from dunex.pii.scanner import RegexPIIScanner
from dunex.injection.detector import PromptInjectionDetector
from dunex.toxicity.evaluator import ToxicityEvaluator

__version__ = "1.0.0"

__all__ = [
    "GuardrailPipeline",
    "GuardrailsMiddleware",
    "GuardrailsConfig",
    "AgentPolicy",
    "AgentPolicyRegistry",
    "PolicyViolation",
    "AuditLogger",
    "DynamoDBAuditItem",
    "GuardrailVerdict",
    "MaskingStrategy",
    "PIIType",
    "PIIDetection",
    "InjectionType",
    "InjectionDetection",
    "InspectionRequest",
    "InspectionResult",
    "ToxicityScore",
    "PIIMasker",
    "RegexPIIScanner",
    "PromptInjectionDetector",
    "ToxicityEvaluator",
]

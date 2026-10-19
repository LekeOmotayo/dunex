"""
Signatures, attack patterns, and regex heuristics for prompt injection detection.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple
from dunex.models import InjectionType

# Regex patterns mapped to specific injection types and base severity scores
INJECTION_SIGNATURES: List[Tuple[InjectionType, re.Pattern, float, str]] = [
    # ── 1. System Prompt Overrides ───────────────────────────────────────────
    (
        InjectionType.SYSTEM_PROMPT_OVERRIDE,
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget|override|neglect|dismiss)\s+(?:all\s+)?(?:previous|prior|above|former|initial)\s+(?:instructions|prompts|directives|rules|constraints|guidelines)\b"
        ),
        0.95,
        "Explicit directive to disregard or overwrite preceding system instructions.",
    ),
    (
        InjectionType.SYSTEM_PROMPT_OVERRIDE,
        re.compile(
            r"(?i)\b(?:new\s+system\s+prompt|new\s+instructions\s+follow|start\s+fresh|reset\s+instructions|clear\s+memory)\b"
        ),
        0.85,
        "System prompt boundary reset indicator.",
    ),
    (
        InjectionType.SYSTEM_PROMPT_OVERRIDE,
        re.compile(
            r"(?i)\b(?:reveal|print|output|display|show|repeat)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|hidden\s+rules|internal\s+instructions|secret\s+key)\b"
        ),
        0.90,
        "Prompt leak or internal system prompt exfiltration attempt.",
    ),

    # ── 2. Jailbreaks & DAN Modes ───────────────────────────────────────────
    (
        InjectionType.JAILBREAK,
        re.compile(
            r"(?i)\b(?:do\s+anything\s+now|dan\s+mode|jailbreak(?:ed)?|unfiltered\s+mode|chaos\s+mode|developer\s+mode\s+enabled|god\s+mode|unrestricted\s+ai)\b"
        ),
        0.98,
        "Known jailbreak persona activation phrase (DAN/Developer mode).",
    ),
    (
        InjectionType.JAILBREAK,
        re.compile(
            r"(?i)\b(?:bypass|ignore|disable|turn\s+off)\s+(?:all\s+)?(?:safety|content|ethical|security)\s+(?:filters|protocols|boundaries|checks|guidelines)\b"
        ),
        0.92,
        "Explicit attempt to disable safety and content filters.",
    ),

    # ── 3. Role Reversal & Persona Hijacking ─────────────────────────────────
    (
        InjectionType.ROLE_REVERSAL,
        re.compile(
            r"(?i)\b(?:you\s+are\s+no\s+longer|act\s+as\s+if\s+you\s+have\s+no\s+rules|pretend\s+to\s+be\s+an\s+evil|you\s+must\s+obey\s+only\s+me)\b"
        ),
        0.88,
        "Persona hijacking or forced adversarial role assumption.",
    ),
    (
        InjectionType.ROLE_REVERSAL,
        re.compile(
            r"(?i)\b(?:for\s+hypothetical\s+purposes|in\s+an\s+unregulated\s+fictional\s+world|without\s+any\s+moral\s+restraints)\b"
        ),
        0.70,
        "Fictional/hypothetical framing used to circumvent ethical restrictions.",
    ),

    # ── 4. Delimiter Escapes & Special Tokens ─────────────────────────────────
    (
        InjectionType.DELIMITER_ESCAPE,
        re.compile(
            r"(?:<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>|<s>|</s>)"
        ),
        0.95,
        "Model-level delimiter injection token attempting prompt framing bypass.",
    ),
    (
        InjectionType.DELIMITER_ESCAPE,
        re.compile(
            r"(?:</system>\s*<system>|</instruction>\s*<instruction>|```system\s+role)"
        ),
        0.85,
        "Structural XML/Markdown markup mimicking system-level prompt tags.",
    ),

    # ── 5. Unrestricted Mode / Compliance Pressure ───────────────────────────
    (
        InjectionType.UNRESTRICTED_MODE,
        re.compile(
            r"(?i)\b(?:you\s+must\s+answer|do\s+not\s+say\s+you\s+cannot|never\s+refuse|your\s+safety\s+filter\s+is\s+broken)\b"
        ),
        0.65,
        "Coercive instruction designed to bypass refusals.",
    ),
]

"""
High-throughput toxicity and content harm vector evaluator.
Inspects text across harassment, hate speech, threats, and dangerous content.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple
from dunex.models import ToxicityScore

# Harm categories with weighted lexicons & patterns
HARM_PATTERNS: Dict[str, List[Tuple[re.Pattern, float]]] = {
    "threat": [
        (re.compile(r"(?i)\b(?:i\s+will|going\s+to)\s+(?:kill|murder|shoot|stab|destroy|hurt|bomb)\s+you\b"), 0.98),
        (re.compile(r"(?i)\b(?:hope\s+you\s+die|deserve\s+to\s+die|burn\s+in\s+hell)\b"), 0.90),
        (re.compile(r"(?i)\b(?:execute|slaughter|assassinate)\s+(?:them|him|her|you|all)\b"), 0.95),
    ],
    "hate_speech": [
        (re.compile(r"(?i)\b(?:subhuman|vermin|parasites)\b"), 0.85),
        (re.compile(r"(?i)\b(?:inferior\s+race|racial\s+slur|ethnic\s+cleansing)\b"), 0.95),
    ],
    "harassment": [
        (re.compile(r"(?i)\b(?:you\s+are\s+(?:worthless|stupid|idiot|trash|garbage|pathetic))\b"), 0.75),
        (re.compile(r"(?i)\b(?:nobody\s+likes\s+you|kill\s+yourself|kys)\b"), 0.98),
    ],
    "dangerous_content": [
        (re.compile(r"(?i)\b(?:how\s+to\s+build\s+a\s+(?:bomb|explosive|weapon|poison))\b"), 0.98),
        (re.compile(r"(?i)\b(?:synthesize\s+(?:ricin|sarin|anthrax|cyanide))\b"), 0.99),
    ],
}


class ToxicityEvaluator:
    """Evaluates text against toxicity, threat, and harm vectors."""

    def __init__(self, default_threshold: float = 0.50) -> None:
        self.default_threshold = default_threshold

    def evaluate(self, text: str, threshold: float | None = None) -> ToxicityScore:
        """Scan text and return detailed toxicity category scoring."""
        thresh = threshold if threshold is not None else self.default_threshold
        if not text:
            return ToxicityScore(score=0.0, flagged=False)

        categories: Dict[str, float] = {}
        matched_terms: List[str] = []
        max_score = 0.0

        for category, patterns in HARM_PATTERNS.items():
            cat_max = 0.0
            for pattern, weight in patterns:
                m = pattern.search(text)
                if m:
                    matched_terms.append(f"{category}:{m.group(0)}")
                    if weight > cat_max:
                        cat_max = weight
            categories[category] = cat_max
            if cat_max > max_score:
                max_score = cat_max

        flagged = max_score >= thresh
        return ToxicityScore(
            score=round(max_score, 3),
            flagged=flagged,
            categories=categories,
            matched_terms=matched_terms,
        )

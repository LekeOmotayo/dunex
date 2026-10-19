"""
Lightweight local token classifier for context-aware secret and PII detection.
Uses Shannon entropy analysis and context-window token scoring without heavy ML dependencies.
"""

from __future__ import annotations

import math
import re
from typing import List, Set
from dunex.models import PIIDetection, PIIType, MaskingStrategy
from dunex.pii.maskers import PIIMasker


# High-entropy character set pattern
TOKEN_CANDIDATE_REGEX = re.compile(r"\b[A-Za-z0-9+/=_\-]{16,80}\b")

# Surrounding context keywords indicating credentials or secrets
SECRET_CONTEXT_KEYWORDS: Set[str] = {
    "password", "secret", "passwd", "apikey", "api_key", "token", "auth",
    "bearer", "credential", "private", "access_token", "client_secret",
    "authorization", "signature", "jwt", "session_id", "pin", "ssn",
    "social_security", "card_number", "account_number"
}


def compute_shannon_entropy(token: str) -> float:
    """Calculate Shannon entropy of a string (higher = more random/secret-like)."""
    if not token:
        return 0.0
    entropy = 0.0
    length = len(token)
    counts = {}
    for char in token:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class LocalTokenClassifier:
    """Context-aware heuristic token classifier for zero-shot credential detection."""

    def __init__(self, masker: PIIMasker | None = None) -> None:
        self.masker = masker or PIIMasker()
        self.entropy_threshold = 3.6 # Typical random passwords / secrets have > 3.5 entropy

    def classify(
        self,
        text: str,
        existing_spans: List[PIIDetection] | None = None,
        strategy: MaskingStrategy = MaskingStrategy.REDACT,
    ) -> List[PIIDetection]:
        """Identify high-entropy tokens positioned near security-sensitive context markers."""
        existing_ranges = {(d.start, d.end) for d in (existing_spans or [])}
        detections: List[PIIDetection] = []
        lower_text = text.lower()

        for match in TOKEN_CANDIDATE_REGEX.finditer(text):
            start, end = match.span()
            # Skip if already captured by regex scanner
            if any(s <= start and end <= e for s, e in existing_ranges):
                continue

            raw_token = match.group(0)

            # Ignore pure numeric tokens or standard common camelCase words
            if raw_token.isdigit() or raw_token.isalpha() and raw_token.islower():
                continue

            entropy = compute_shannon_entropy(raw_token)

            # Check context window (50 characters left & right)
            left_window = lower_text[max(0, start - 50) : start]
            right_window = lower_text[end : min(len(lower_text), end + 50)]
            context_has_marker = any(k in left_window or k in right_window for k in SECRET_CONTEXT_KEYWORDS)

            is_secret = False
            confidence = 0.5

            if context_has_marker and entropy >= 3.2:
                is_secret = True
                confidence = 0.88
            elif entropy >= 4.2: # Very high entropy (base64 random string)
                is_secret = True
                confidence = 0.92

            if is_secret:
                masked = self.masker.mask(raw_token, PIIType.GENERIC_SECRET, strategy)
                detections.append(
                    PIIDetection(
                        entity_type=PIIType.GENERIC_SECRET,
                        raw_text=raw_token,
                        masked_text=masked,
                        start=start,
                        end=end,
                        confidence=confidence,
                        detector="token_classifier",
                        metadata={"entropy": round(entropy, 2), "has_context_marker": context_has_marker},
                    )
                )

        return detections

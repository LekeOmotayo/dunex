"""
High-throughput regex-based PII and secret scanner with algorithmic checksum validators.
Includes Luhn algorithm for credit cards, Federal Reserve routing checksums, and strict format heuristics.
"""

from __future__ import annotations

import re
from typing import List, Tuple
from dunex.models import PIIDetection, PIIType, MaskingStrategy
from dunex.pii.maskers import PIIMasker


# ── Luhn Checksum for Credit Card Validation ─────────────────────────────────
def luhn_checksum(card_number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 2:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# ── US Bank Routing Transit Number Checksum ──────────────────────────────────
def bank_routing_checksum(routing: str) -> bool:
    """Validate 9-digit ABA bank routing number via Federal Reserve weighting."""
    digits = [int(c) for c in routing if c.isdigit()]
    if len(digits) != 9:
        return False
    # Weights: 3, 7, 1, 3, 7, 1, 3, 7, 1
    weights = [3, 7, 1, 3, 7, 1, 3, 7, 1]
    s = sum(d * w for d, w in zip(digits, weights))
    return s % 10 == 0


# ── Compiled Patterns ────────────────────────────────────────────────────────
PATTERNS = {
    # SSN: 3 digits - 2 digits - 4 digits (Cannot start with 000, 666, 900-999)
    PIIType.SSN: re.compile(
        r"\b(?!000|666|9\d{2})(\d{3})[- ]?(?!00)(\d{2})[- ]?(?!0000)(\d{4})\b"
    ),
    # Credit Card candidate (Visa, Mastercard, Amex, Discover, Diners)
    PIIType.CREDIT_CARD: re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b"
        r"|\b(?:\d{4}[- ]){3}\d{4}\b"
    ),
    # API Keys: OpenAI, AWS, GitHub, Slack, Private Keys, JWTs
    PIIType.API_KEY: re.compile(
        r"(?:"
        r"\b(?:sk-[a-zA-Z0-9]{32,}|sk-proj-[a-zA-Z0-9_-]{40,})\b|"  # OpenAI
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|"                           # AWS Access Key
        r"\bgh[pousr]_[a-zA-Z0-9]{36,}\b|"                          # GitHub Tokens
        r"\bxox[baprs]-[0-9a-zA-Z-]{24,}\b|"                       # Slack Tokens
        r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b|" # JWT
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"        # PEM Private Key
        r"\b[a-f0-9]{32,64}\b"                                      # Hex secrets (filtered by context)
        r")"
    ),
    # Email addresses (RFC 5322 compliant subset)
    PIIType.EMAIL: re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
    ),
    # Phone numbers: US formats & E.164 international
    PIIType.PHONE_NUMBER: re.compile(
        r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
    # IPv4 Addresses
    PIIType.IP_ADDRESS: re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ),
    # US Bank Routing Transit
    PIIType.BANK_ROUTING: re.compile(
        r"\b(?:0[1-9]|[1-2][0-9]|3[0-2]|6[1-9]|7[0-2]|80)\d{7}\b"
    ),
    # IBAN (International Bank Account Number)
    PIIType.IBAN: re.compile(
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b"
    ),
}


class RegexPIIScanner:
    """Multi-pattern regex scanner with post-match semantic verification."""

    def __init__(self, masker: PIIMasker | None = None) -> None:
        self.masker = masker or PIIMasker()

    def scan(
        self,
        text: str,
        strategy: MaskingStrategy = MaskingStrategy.REDACT,
        allowed_types: List[PIIType] | None = None,
    ) -> List[PIIDetection]:
        """Scan text and return all verified PII detections."""
        allowed = set(allowed_types or [])
        detections: List[PIIDetection] = []

        for entity_type, pattern in PATTERNS.items():
            if entity_type in allowed:
                continue

            for match in pattern.finditer(text):
                raw = match.group(0)
                start, end = match.span()

                # Validation checks for specific types
                if entity_type == PIIType.CREDIT_CARD:
                    cleaned_digits = "".join(c for c in raw if c.isdigit())
                    if not luhn_checksum(cleaned_digits):
                        continue # Skip invalid card numbers

                elif entity_type == PIIType.BANK_ROUTING:
                    if not bank_routing_checksum(raw):
                        continue

                elif entity_type == PIIType.API_KEY and len(raw) in (32, 40, 64) and re.fullmatch(r"[a-f0-9]+", raw):
                    # For plain hex strings, only treat as API_KEY if near secret keywords
                    window = text[max(0, start - 30) : min(len(text), end + 30)].lower()
                    if not any(k in window for k in ("secret", "key", "token", "auth", "api", "pwd")):
                        continue

                masked = self.masker.mask(raw, entity_type, strategy)
                detections.append(
                    PIIDetection(
                        entity_type=entity_type,
                        raw_text=raw,
                        masked_text=masked,
                        start=start,
                        end=end,
                        confidence=0.98 if entity_type in (PIIType.SSN, PIIType.CREDIT_CARD) else 0.92,
                        detector="regex",
                    )
                )

        # De-duplicate overlapping spans by keeping highest confidence or longest span
        return self._deduplicate_spans(detections)

    def _deduplicate_spans(self, detections: List[PIIDetection]) -> List[PIIDetection]:
        """Remove overlapping spans, preferring longer or higher-confidence entities."""
        if not detections:
            return []

        # Sort by start ascending, then length descending
        sorted_dets = sorted(detections, key=lambda d: (d.start, -(d.end - d.start)))
        clean: List[PIIDetection] = []

        current_end = -1
        for det in sorted_dets:
            if det.start >= current_end:
                clean.append(det)
                current_end = det.end
            else:
                # Overlap detected: if this entity is more specific, replace previous
                if clean and (det.end - det.start) > (clean[-1].end - clean[-1].start):
                    clean[-1] = det
                    current_end = det.end

        return clean

    def sanitize(
        self,
        text: str,
        strategy: MaskingStrategy = MaskingStrategy.REDACT,
        allowed_types: List[PIIType] | None = None,
    ) -> Tuple[str, List[PIIDetection]]:
        """Scan text and substitute all detected PII tokens with their masked values."""
        detections = self.scan(text, strategy=strategy, allowed_types=allowed_types)
        if not detections:
            return text, []

        # Reconstruct string from right to left to preserve index offsets
        result = list(text)
        for det in sorted(detections, key=lambda d: d.start, reverse=True):
            result[det.start : det.end] = list(det.masked_text)

        return "".join(result), detections

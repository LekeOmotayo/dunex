"""
Masking strategies for discovered PII tokens.
Provides Redaction, Cryptographic Hashing, Partial Masking, and Format-Preserving Tokenization.
"""

from __future__ import annotations

import hashlib
from typing import Optional
from dunex.models import MaskingStrategy, PIIType


class PIIMasker:
    """Applies configured masking strategies to discovered PII tokens."""

    def __init__(self, salt: str = "dunex-salt-2026") -> None:
        self.salt = salt

    def mask(
        self,
        raw_value: str,
        entity_type: PIIType,
        strategy: MaskingStrategy = MaskingStrategy.REDACT,
    ) -> str:
        """Apply masking according to the specified strategy."""
        if strategy == MaskingStrategy.REDACT:
            return f"[REDACTED_{entity_type.value}]"

        if strategy == MaskingStrategy.HASH:
            digest = hashlib.sha256(f"{self.salt}:{raw_value}".encode("utf-8")).hexdigest()
            return f"[SHA256:{digest[:12]}]"

        if strategy == MaskingStrategy.TOKENIZE:
            short_hash = hashlib.md5(f"{self.salt}:{raw_value}".encode("utf-8")).hexdigest()[:8]
            return f"[TOKEN_{entity_type.value}_{short_hash.upper()}]"

        if strategy == MaskingStrategy.MASK_PARTIAL:
            return self._mask_partial(raw_value, entity_type)

        return f"[REDACTED_{entity_type.value}]"

    def _mask_partial(self, val: str, entity_type: PIIType) -> str:
        """Preserve standard hints while masking identifying portions."""
        clean = val.strip()

        if entity_type == PIIType.SSN:
            # Display only last 4 digits: ***-**-1234
            digits = "".join(c for c in clean if c.isdigit())
            if len(digits) == 9:
                return f"***-**-{digits[-4:]}"
            return "***-**-****"

        if entity_type == PIIType.CREDIT_CARD:
            # Display only last 4 digits: ****-****-****-1234
            digits = "".join(c for c in clean if c.isdigit())
            if len(digits) >= 13:
                return f"****-****-****-{digits[-4:]}"
            return "****-****-****-****"

        if entity_type == PIIType.EMAIL:
            # e.g., j***@example.com
            parts = clean.split("@")
            if len(parts) == 2:
                user, domain = parts
                masked_user = user[0] + "***" if len(user) > 1 else "***"
                return f"{masked_user}@{domain}"
            return "[REDACTED_EMAIL]"

        if entity_type == PIIType.API_KEY:
            # Keep prefix (e.g. sk-...) and suffix (last 4)
            if len(clean) > 8:
                return f"{clean[:3]}...{clean[-4:]}"
            return "[REDACTED_API_KEY]"

        if entity_type == PIIType.PHONE_NUMBER:
            digits = "".join(c for c in clean if c.isdigit())
            if len(digits) >= 10:
                return f"(***) ***-{digits[-4:]}"
            return "(***) ***-****"

        if entity_type == PIIType.BANK_ROUTING:
            digits = "".join(c for c in clean if c.isdigit())
            if len(digits) == 9:
                return f"*****{digits[-4:]}"
            return "*********"

        # Default fallback
        if len(clean) > 4:
            return clean[:1] + "*" * (len(clean) - 2) + clean[-1:]
        return "*" * len(clean)

"""
Active Prompt Injection and Jailbreak Detector.
Includes Unicode homoglyph normalization, zero-width stripping, and multi-tier pattern matching.
"""

from __future__ import annotations

import unicodedata
from typing import List, Tuple
from dunex.models import InjectionDetection, InjectionType
from dunex.injection.signatures import INJECTION_SIGNATURES


# Common homoglyph substitution map to defeat adversarial character obfuscation
HOMOGLYPHS = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y', # Cyrillic
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'О': 'O', 'Р': 'P',
    '@': 'a', '$': 's', '0': 'o', '1': 'i', '!': 'i', '3': 'e'
}


class PromptInjectionDetector:
    """Detects adversarial prompt injections, jailbreaks, and delimiter escapes."""

    def __init__(self, sensitivity_threshold: float = 0.65) -> None:
        self.sensitivity_threshold = sensitivity_threshold

    def normalize(self, text: str) -> str:
        """Strip zero-width characters, normalize unicode, and resolve homoglyphs."""
        # 1. Unicode NFKC normalization
        norm = unicodedata.normalize("NFKC", text)

        # 2. Strip invisible zero-width spaces / joiners
        zero_width = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u00ad", "\u2060"}
        for ch in zero_width:
            norm = norm.replace(ch, "")

        # 3. Simple homoglyph translation for clean analysis
        translated = []
        for ch in norm:
            translated.append(HOMOGLYPHS.get(ch, ch))

        return "".join(translated)

    def scan(self, text: str) -> Tuple[List[InjectionDetection], float]:
        """
        Scan text for prompt injection vectors.
        Returns (list_of_detections, cumulative_risk_score).
        """
        if not text:
            return [], 0.0

        normalized = self.normalize(text)
        detections: List[InjectionDetection] = []
        max_score = 0.0

        for attack_type, pattern, base_score, explanation in INJECTION_SIGNATURES:
            match = pattern.search(normalized)
            if match:
                matched_span = match.group(0)
                severity = "CRITICAL" if base_score >= 0.90 else "HIGH" if base_score >= 0.80 else "MEDIUM"
                
                detections.append(
                    InjectionDetection(
                        attack_type=attack_type,
                        matched_pattern=matched_span,
                        risk_score=base_score,
                        severity=severity,
                        explanation=explanation,
                    )
                )
                if base_score > max_score:
                    max_score = base_score

        # Combine multiple detections into cumulative risk score
        if len(detections) > 1:
            # Diminishing returns formula: 1 - prod(1 - s)
            cumulative = 1.0
            for d in detections:
                cumulative *= (1.0 - d.risk_score * 0.7)
            combined_score = round(min(1.0, 1.0 - cumulative), 3)
            max_score = max(max_score, combined_score)

        return detections, round(max_score, 3)

    def is_flagged(self, text: str, threshold: float | None = None) -> bool:
        """Boolean check whether text exceeds injection risk threshold."""
        thresh = threshold if threshold is not None else self.sensitivity_threshold
        _, score = self.scan(text)
        return score >= thresh

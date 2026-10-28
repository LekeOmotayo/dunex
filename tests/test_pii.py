"""
Tests for PII scanner, Luhn check, API key detection, and masking strategies.
"""

from dunex.models import MaskingStrategy, PIIType
from dunex.pii.maskers import PIIMasker
from dunex.pii.scanner import RegexPIIScanner, luhn_checksum, bank_routing_checksum
from dunex.pii.classifier import LocalTokenClassifier, compute_shannon_entropy


def test_luhn_algorithm():
    # Valid credit cards
    assert luhn_checksum("4532015012345671") is True
    assert luhn_checksum("4532-0150-1234-5671") is True
    assert luhn_checksum("49927398716") is True

    # Invalid cards
    assert luhn_checksum("4532015012345679") is False
    assert luhn_checksum("1234567812345678") is False
    assert luhn_checksum("123") is False


def test_bank_routing_checksum():
    # Valid ABA routing number (Chase Manhattan 021000021)
    assert bank_routing_checksum("021000021") is True
    # Invalid
    assert bank_routing_checksum("021000022") is False
    assert bank_routing_checksum("1234") is False


def test_masking_strategies():
    masker = PIIMasker(salt="test-salt")
    val = "452-82-9182"

    # Redact
    assert masker.mask(val, PIIType.SSN, MaskingStrategy.REDACT) == "[REDACTED_SSN]"

    # Hash
    hashed = masker.mask(val, PIIType.SSN, MaskingStrategy.HASH)
    assert hashed.startswith("[SHA256:") and hashed.endswith("]")

    # Tokenize
    token = masker.mask(val, PIIType.SSN, MaskingStrategy.TOKENIZE)
    assert token.startswith("[TOKEN_SSN_") and token.endswith("]")

    # Partial Mask
    partial = masker.mask(val, PIIType.SSN, MaskingStrategy.MASK_PARTIAL)
    assert partial == "***-**-9182"


def test_mask_partial_varieties():
    masker = PIIMasker()
    # Credit Card
    assert masker.mask("4532015012345678", PIIType.CREDIT_CARD, MaskingStrategy.MASK_PARTIAL) == "****-****-****-5678"
    # Email
    assert masker.mask("john.doe@gmail.com", PIIType.EMAIL, MaskingStrategy.MASK_PARTIAL) == "j***@gmail.com"
    # API Key
    assert masker.mask("sk-1234567890abcdef1234567890", PIIType.API_KEY, MaskingStrategy.MASK_PARTIAL) == "sk-...7890"
    # Phone
    assert masker.mask("4155551234", PIIType.PHONE_NUMBER, MaskingStrategy.MASK_PARTIAL) == "(***) ***-1234"


def test_regex_scanner_ssn_and_email():
    scanner = RegexPIIScanner()
    text = "User Jane Doe with SSN 452-82-9182 contacted support@company.org regarding her account."
    sanitized, detections = scanner.sanitize(text, strategy=MaskingStrategy.REDACT)

    assert "[REDACTED_SSN]" in sanitized
    assert "[REDACTED_EMAIL]" in sanitized
    assert "452-82-9182" not in sanitized
    assert len(detections) == 2
    types = {d.entity_type for d in detections}
    assert PIIType.SSN in types
    assert PIIType.EMAIL in types


def test_regex_scanner_api_keys():
    scanner = RegexPIIScanner()
    text = (
        "Deployment keys: "
        "OPENAI_KEY=sk-proj-abC123deF456ghI789jkL012mnO345pqR678stU901vwX234 and "
        "AWS=AKIAIOSFODNN7EXAMPLE and "
        "GH=ghp_ABC123def456GHI789jkl012MNO345pqr678."
    )
    sanitized, detections = scanner.sanitize(text, strategy=MaskingStrategy.REDACT)

    assert "sk-proj-" not in sanitized
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
    assert "ghp_ABC123def456GHI789jkl012MNO345pqr678" not in sanitized
    assert len(detections) >= 3


def test_token_classifier_entropy():
    # Common English word has low entropy
    low_ent = compute_shannon_entropy("password")
    assert low_ent < 3.2

    # High entropy base64-like random secret
    high_ent = compute_shannon_entropy("kX9#vL2!mP9$qR8@zW4^")
    assert high_ent > 3.8


def test_token_classifier_context_detection():
    classifier = LocalTokenClassifier()
    # High entropy token near a secret keyword
    text = "The database secret_key is zK89bX44mQ12wR77pL09vN88 which is used to sign cookies."
    detections = classifier.classify(text)

    assert len(detections) >= 1
    assert detections[0].entity_type == PIIType.GENERIC_SECRET

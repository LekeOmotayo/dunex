"""
Tests for toxicity and content harm evaluator.
"""

from dunex.toxicity.evaluator import ToxicityEvaluator


def test_threat_detection():
    evaluator = ToxicityEvaluator(default_threshold=0.50)
    text = "I will find where you live and kill you."
    score = evaluator.evaluate(text)

    assert score.flagged is True
    assert score.score >= 0.90
    assert score.categories.get("threat", 0.0) >= 0.90
    assert len(score.matched_terms) >= 1


def test_harassment_detection():
    evaluator = ToxicityEvaluator()
    text = "You are worthless and stupid and nobody likes you."
    score = evaluator.evaluate(text)

    assert score.flagged is True
    assert score.categories.get("harassment", 0.0) >= 0.70


def test_dangerous_content_detection():
    evaluator = ToxicityEvaluator()
    text = "Instructions on how to build a bomb with household supplies."
    score = evaluator.evaluate(text)

    assert score.flagged is True
    assert score.categories.get("dangerous_content", 0.0) >= 0.90


def test_benign_text_safe():
    evaluator = ToxicityEvaluator()
    text = "Could you please explain how photosythesis works in green plants?"
    score = evaluator.evaluate(text)

    assert score.flagged is False
    assert score.score == 0.0

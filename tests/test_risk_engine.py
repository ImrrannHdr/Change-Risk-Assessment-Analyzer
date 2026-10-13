from src.common.models import Finding
from src.risk_engine import evaluate


def test_hard_block_overrides_score():
    findings = [
        Finding(
            category="TEST",
            severity="CRITICAL",
            risk_points=10,
            resource="demo",
            message="danger",
            hard_block=True,
        )
    ]
    result = evaluate(findings)
    assert result.decision == "BLOCK"


def test_prod_modifier_applied():
    findings = [
        Finding(
            category="TEST",
            severity="LOW",
            risk_points=20,
            resource="demo",
            message="test",
        )
    ]
    result = evaluate(findings, environment="prod")
    assert result.risk_score == 30
    assert result.decision == "APPROVAL_REQUIRED"

# Build by Imran Haider

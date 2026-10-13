from src.common.models import AnalysisResult, Finding


def _level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def evaluate(findings: list[Finding], environment: str = "dev") -> AnalysisResult:
    score = sum(f.risk_points for f in findings)

    if environment.lower() == "prod" and findings:
        score += 10

    score = min(score, 100)
    level = _level(score)
    hard_block = any(f.hard_block for f in findings)

    if hard_block or level == "CRITICAL":
        decision = "BLOCK"
    elif level in {"HIGH", "MEDIUM"}:
        decision = "APPROVAL_REQUIRED"
    else:
        decision = "ALLOW"

    return AnalysisResult(
        risk_score=score,
        risk_level=level,
        decision=decision,
        findings=findings,
    )

# Build by Imran Haider

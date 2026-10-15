
from functools import lru_cache
from pathlib import Path
import yaml

from src.common.models import AnalysisResult, Finding


# Locate the risk policy relative to the project root.
POLICY_PATH = (
    Path(__file__).resolve().parent.parent
    / "config"
    / "risk_policy.yaml"
)


@lru_cache(maxsize=1)
def load_policy() -> dict:
    """Load and validate risk scoring configuration from YAML."""

    with POLICY_PATH.open("r", encoding="utf-8") as file:
        policy = yaml.safe_load(file)

    if not isinstance(policy, dict):
        raise ValueError("Risk policy must be a YAML mapping")

    thresholds = policy.get("risk_thresholds")
    modifiers = policy.get("environment_modifiers")

    if not isinstance(thresholds, dict):
        raise ValueError("Missing or invalid risk_thresholds")

    if not isinstance(modifiers, dict):
        raise ValueError("Missing or invalid environment_modifiers")

    required_thresholds = ("medium", "high", "critical")

    for key in required_thresholds:
        value = thresholds.get(key)

        if type(value) is not int or not 0 <= value <= 100:
            raise ValueError(
                f"Invalid risk threshold for {key}: {value}"
            )

    if not (
        thresholds["medium"]
        < thresholds["high"]
        < thresholds["critical"]
    ):
        raise ValueError(
            "Risk thresholds must satisfy medium < high < critical"
        )

    for environment, modifier in modifiers.items():
        if type(modifier) is not int:
            raise ValueError(
                f"Invalid modifier for environment {environment}"
            )

    return policy


def get_environment_modifier(environment: str) -> int:
    """Return the configured environment risk modifier."""

    policy = load_policy()
    modifiers = policy["environment_modifiers"]

    if environment not in modifiers:
        raise ValueError(
            f"Unknown environment: {environment}"
        )

    return modifiers[environment]


def classify_risk(score: int) -> str:
    """Classify a risk score using YAML-defined thresholds."""

    thresholds = load_policy()["risk_thresholds"]

    if score >= thresholds["critical"]:
        return "CRITICAL"

    if score >= thresholds["high"]:
        return "HIGH"

    if score >= thresholds["medium"]:
        return "MEDIUM"

    return "LOW"


def evaluate(
    findings: list[Finding],
    environment: str = "dev"
) -> AnalysisResult:
    """Evaluate security findings and determine deployment decision."""
    print(f"\n--> Evaluating {len(findings)} total findings for environment '{environment}'...")
    # Sum all risk points from the analyzers.
    score = sum(f.risk_points for f in findings)

    # Apply environment modifier only when findings exist.
    if findings:
        score += get_environment_modifier(environment)

    # Keep the score within 0-100.
    score = max(0, min(100, score))
    
    # Determine risk level using YAML thresholds.
    risk_level = classify_risk(score)

    # Check whether any finding requires a hard block.
    hard_block = any(f.hard_block for f in findings)

    # Determine deployment decision.
    if hard_block or risk_level == "CRITICAL":
        decision = "BLOCK"

    elif risk_level in ("HIGH", "MEDIUM"):
        decision = "APPROVAL_REQUIRED"

    else:
        decision = "ALLOW"

    print(f"--> Evaluation complete. Final decision: {decision}, Risk Level: {risk_level}")

    # Return the final analysis result.
    return AnalysisResult(
        risk_score=score,
        risk_level=risk_level,
        decision=decision,
        findings=findings,
    )


# Build by Imran Haider

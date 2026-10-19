from typing import Any

from src.common.models import Change, Finding

SENSITIVE_ACTION_PREFIXES = ("iam:", "kms:", "secretsmanager:", "sts:")


def _flatten_actions(document: dict[str, Any] | None) -> set[str]:
    if not isinstance(document, dict):
        return set()

    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    actions: set[str] = set()
    for statement in statements:
        action = statement.get("Action", []) if isinstance(statement, dict) else []
        if isinstance(action, str):
            actions.add(action)
        elif isinstance(action, list):
            actions.update(str(x) for x in action)
    return actions


def analyze(changes: list[Change]) -> list[Finding]:
    findings: list[Finding] = []

    for change in changes:
        if "iam" not in change.resource_type:
            continue

        before_policy = (change.before or {}).get("policy")
        after_policy = (change.after or {}).get("policy")

        # Terraform may expose policy as a decoded object in fixtures or a string in real plans.
        if isinstance(before_policy, str) or isinstance(after_policy, str):
            continue

        before_actions = _flatten_actions(before_policy)
        after_actions = _flatten_actions(after_policy)
        added = after_actions - before_actions

        wildcards = sorted(a for a in added if a == "*" or a.endswith(":*"))
        if wildcards:
            findings.append(
                Finding(
                    category="IAM_WILDCARD",
                    severity="HIGH",
                    risk_points=30,
                    resource=change.address,
                    message="IAM wildcard permission introduced.",
                    evidence={"added_actions": wildcards},
                )
            )

        sensitive = sorted(
            a for a in added if a.startswith(SENSITIVE_ACTION_PREFIXES)
        )
        if sensitive:
            findings.append(
                Finding(
                    category="IAM_SENSITIVE_ACTION",
                    severity="MEDIUM",
                    risk_points=20,
                    resource=change.address,
                    message="Sensitive IAM/KMS/Secrets/STS action introduced.",
                    evidence={"added_actions": sensitive},
                )
            )

        if "iam:PassRole" in added:
            findings.append(
                Finding(
                    category="IAM_PASSROLE_EXPANSION",
                    severity="HIGH",
                    risk_points=25,
                    resource=change.address,
                    message="iam:PassRole permission introduced.",
                    evidence={"added_actions": ["iam:PassRole"]},
                )
            )

    print(f"Found {len(findings)} IAM findings.")
    return findings

# Build by Imran Haider

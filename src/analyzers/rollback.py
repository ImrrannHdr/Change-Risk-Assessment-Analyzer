from src.common.models import Change, Finding

STATEFUL_TYPES = {
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_ebs_volume",
    "aws_dynamodb_table",
}


def analyze(changes: list[Change]) -> list[Finding]:
    findings: list[Finding] = []

    for change in changes:
        if change.replacement:
            points = 35 if change.resource_type in STATEFUL_TYPES else 20
            findings.append(
                Finding(
                    category="RESOURCE_REPLACEMENT",
                    severity="HIGH" if points >= 35 else "MEDIUM",
                    risk_points=points,
                    resource=change.address,
                    message="Terraform plan requires resource replacement.",
                    evidence={"resource_type": change.resource_type},
                )
            )

        if change.actions == ["delete"] and change.resource_type in STATEFUL_TYPES:
            findings.append(
                Finding(
                    category="STATEFUL_DELETE",
                    severity="CRITICAL",
                    risk_points=50,
                    resource=change.address,
                    message="Stateful resource deletion detected.",
                    evidence={"resource_type": change.resource_type},
                    hard_block=True,
                )
            )

    return findings

# Build by Imran Haider

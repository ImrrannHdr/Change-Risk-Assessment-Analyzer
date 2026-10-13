from src.common.models import Change, Finding

# Deliberately simple MVP heuristics. Pricing API integration can replace these later.
INSTANCE_WEIGHT = {
    "t3.micro": 1,
    "t3.small": 2,
    "t3.medium": 4,
    "m6i.large": 8,
    "m6i.xlarge": 16,
}


def analyze(changes: list[Change]) -> list[Finding]:
    findings: list[Finding] = []

    for change in changes:
        if change.resource_type == "aws_instance":
            before_type = (change.before or {}).get("instance_type")
            after_type = (change.after or {}).get("instance_type")
            if before_type in INSTANCE_WEIGHT and after_type in INSTANCE_WEIGHT:
                if INSTANCE_WEIGHT[after_type] > INSTANCE_WEIGHT[before_type]:
                    findings.append(
                        Finding(
                            category="COST_INCREASE",
                            severity="LOW",
                            risk_points=5,
                            resource=change.address,
                            message="EC2 instance size increases estimated cost.",
                            evidence={"before": before_type, "after": after_type},
                        )
                    )

    return findings

# Build by Imran Haider

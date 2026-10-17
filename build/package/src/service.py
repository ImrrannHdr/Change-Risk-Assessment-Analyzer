
from typing import Any, Callable

from src.analyzers import cost, iam, network, rollback
from src.parser import parse_tfplan
from src.risk_engine import evaluate
from src.context.blast_radius import (
    analyze_security_group_impact,
)


def analyze_plan(
    plan: dict,
    environment: str = "dev",
    enable_context: bool = False,
    resource_collector: Callable | None = None,
    region: str = "ap-southeast-2",
):
    changes = parse_tfplan(plan)
    findings = []

    # IAM risk analysis
    findings.extend(iam.analyze(changes))

    # Network risk analysis
    network_findings = network.analyze(
        changes,
        plan=plan,
    )

    # Optional context-aware investigation
    if enable_context:
        for finding in network_findings:

            if finding.category != "INTERNET_EXPOSURE":
                continue

            try:
                context = analyze_security_group_impact(
                    plan=plan,
                    rule_address=finding.resource,
                    region=region,
                    resource_collector=resource_collector,
                )

                finding.evidence["blast_radius"] = context

            except Exception as error:
                # Never interpret discovery failure
                # as zero affected resources.
                finding.evidence["blast_radius"] = {
                    "status": "CONTEXT_ERROR",
                    "context_complete": False,
                    "existing_dependencies": None,
                    "planned_dependencies": None,
                    "message": (
                        "Context investigation failed: "
                        f"{type(error).__name__}"
                    ),
                }

    findings.extend(network_findings)

    # Cost risk analysis
    findings.extend(cost.analyze(changes))

    # Rollback risk analysis
    findings.extend(rollback.analyze(changes))

    # Existing risk scoring and decision logic
    return evaluate(
        findings,
        environment=environment,
    )

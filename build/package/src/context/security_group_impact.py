
from typing import Any, Callable

from src.analyzers.security_group_changes import (
    detect_security_group_changes,
)
from src.context.blast_radius import (
    analyze_security_group_impact,
)
from src.context.ec2_context import (
    get_security_group_resources,
)


def analyze_all_security_group_impacts(
    plan: dict[str, Any],
    region: str = "ap-southeast-2",
    resource_collector: Callable | None = None,
) -> list[dict[str, Any]]:
    """
    Investigate all detected security group changes.

    Returns impact records independently of scored
    INTERNET_EXPOSURE findings.
    """

    changes = detect_security_group_changes(plan)
    collector = resource_collector or get_security_group_resources

    impacts = []

    for change in changes:
        record = dict(change)
        address = change["resource"]
        sg_id = change.get("security_group_id")

        # Metadata-only changes need no network investigation.
        if change["classification"] == "METADATA_ONLY":
            record["impact"] = {
                "status": "NOT_APPLICABLE",
                "context_complete": False,
                "message": "Only metadata changes were identified.",
            }

        # SG lifecycle changes need special treatment.
        elif (
            change.get("lifecycle_action")
            or "delete" in change["terraform_actions"]
            and "create" in change["terraform_actions"]
        ):
            record["impact"] = {
                "status": "LIFECYCLE_CHANGE",
                "context_complete": False,
                "message": (
                    "Replacement or lifecycle change requires "
                    "before/after attachment analysis."
                ),
            }

        else:
            try:
                if change["resource_type"] == "aws_security_group":
                    # Inline rules have the SG ID on the
                    # parent SG resource, not a standalone rule.
                    if not isinstance(sg_id, str) or not sg_id.startswith("sg-"):
                        record["impact"] = {
                            "status": "UNRESOLVED",
                            "context_complete": False,
                            "message": (
                                "No existing AWS SG ID available. "
                                "Planned dependencies require analysis."
                            ),
                        }
                    else:
                        aws_context = collector(
                            security_group_id=sg_id,
                            region=region,
                        )

                        record["impact"] = {
                            "status": "RESOLVED",
                            "security_group_id": sg_id,
                            "existing_dependencies": aws_context,
                            "planned_dependencies": None,
                            "context_complete": False,
                        }

                else:
                    # Reuse the existing standalone-rule
                    # blast-radius analyzer.
                    record["impact"] = analyze_security_group_impact(
                        plan=plan,
                        rule_address=address,
                        region=region,
                        resource_collector=resource_collector,
                    )

            except Exception as error:
                record["impact"] = {
                    "status": "CONTEXT_ERROR",
                    "context_complete": False,
                    "message": (
                        "Investigation failed: "
                        f"{type(error).__name__}"
                    ),
                }

        impacts.append(record)

    return impacts

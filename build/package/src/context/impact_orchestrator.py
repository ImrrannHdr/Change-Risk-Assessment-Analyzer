"""Independent classification and best-effort SG impact discovery.

No changes are made to risk points or deployment decisions here.
"""
from typing import Any, Callable

from src.analyzers.security_group_changes import detect_security_group_changes
from src.context.blast_radius import analyze_security_group_impact
from src.context.planned_sg_dependencies import find_planned_dependencies
from src.context.sg_lifecycle import analyze_sg_lifecycle

STANDALONE_RULE_TYPES = {
    "aws_security_group_rule",
    "aws_vpc_security_group_ingress_rule",
    "aws_vpc_security_group_egress_rule",
}


def analyze_all_sg_changes(
    plan: dict[str, Any],
    region: str = "ap-southeast-2",
    resource_collector: Callable | None = None,
) -> list[dict[str, Any]]:
    """Return an impact record for every SG change, even if no risk finding exists.

    Whole-SG and inline-rule changes are explicitly NOT_ASSESSED until
    an SG-level resolver is implemented. Existing rule resolver limitations
    remain visible as UNRESOLVED rather than pretending a complete analysis.
    """
    changes = detect_security_group_changes(plan)

    # Whole-SG create/delete/replace operations should generate
    # one lifecycle record, not duplicate ingress/egress records.
    lifecycle_addresses = set()

    for change in changes:
        if (
            change.get("resource_type") == "aws_security_group"
            and change.get("classification") == "LIFECYCLE_CHANGE"
        ):
            address = change["resource"]

            terraform_change = next(
                (
                    resource
                    for resource in plan.get("resource_changes", [])
                    if resource.get("address") == address
                ),
                None,
            )

            actions = (
                (terraform_change or {}).get("change", {}).get("actions", [])
            )

            if "create" in actions or "delete" in actions:
                lifecycle_addresses.add(address)

    # Retain the lifecycle record, suppress redundant inline records.
    changes = [
        change
        for change in changes
        if not (
            change.get("resource") in lifecycle_addresses
            and change.get("resource_type") == "aws_security_group"
            and change.get("classification") != "LIFECYCLE_CHANGE"
        )
    ]




    results: list[dict[str, Any]] = []
    print(f"[IMPACT] Independent scan: {len(changes)} SG changes", flush=True)

    for change in changes:
        address = change["resource"]
        resource_type = change["resource_type"]
        record = dict(change)
        
        # Normalise the outer lifecycle action to match the
# operation returned by sg_lifecycle.py.
    if resource_type == "aws_security_group":
        actions = change.get("terraform_actions", [])

        if "create" in actions and "delete" in actions:
            lifecycle_action = "REPLACE"
        elif actions == ["create"]:
            lifecycle_action = "CREATE"
        elif actions == ["delete"]:
            lifecycle_action = "DELETE"
        elif actions == ["update"]:
            lifecycle_action = "UPDATE"
        else:
            lifecycle_action = "OTHER"

        if change.get("classification") == "LIFECYCLE_CHANGE":
            record["lifecycle_action"] = lifecycle_action
        
        
        print(f"[IMPACT] {address}: {change['classification']}", flush=True)

        if resource_type == "aws_security_group":
            try:
                record["impact"] = analyze_sg_lifecycle(
                    plan=plan,
                    sg_address=address,
                    region=region,
                    resource_collector=resource_collector,
                )
            except Exception as error:
                record["impact"] = {
                    "status": "CONTEXT_ERROR", "context_complete": False,
                    "existing_dependencies": None, "planned_dependencies": None,
                    "message": f"Whole-SG analysis failed: {type(error).__name__}",
                }
        elif resource_type not in STANDALONE_RULE_TYPES:
            record["impact"] = {
                "status": "NOT_ASSESSED",
                "context_complete": False,
                "existing_dependencies": None,
                "planned_dependencies": None,
                "message": "Unsupported SG resource type",
            }
        else:
            try:
                record["impact"] = analyze_security_group_impact(
                    plan=plan,
                    rule_address=address,
                    region=region,
                    resource_collector=resource_collector,
                )
            except Exception as error:
                print(f"[IMPACT] ERROR {address}: {error}", flush=True)
                record["impact"] = {
                    "status": "CONTEXT_ERROR",
                    "context_complete": False,
                    "existing_dependencies": None,
                    "planned_dependencies": None,
                    "message": f"Context investigation failed: {type(error).__name__}",
                }
        # Enrich standalone SG rules with planned EC2/ENI dependencies.
        # Preserve live AWS discovery status and existing risk scoring.
        if resource_type in STANDALONE_RULE_TYPES:
            impact = record["impact"]
            try:
                planned = find_planned_dependencies(
                    plan,
                    security_group_id=(impact.get("security_group_id") or change.get("security_group_id")),
                    security_group_address=impact.get("security_group_address"),
                )
                impact["planned_dependencies"] = planned
                print(f"[PLANNED-IMPACT] {address}: {planned['resource_count']} matched resources", flush=True)
            except Exception as error:
                print(f"[PLANNED-IMPACT] ERROR {address}: {error}", flush=True)
                impact["planned_dependencies"] = {"status": "ERROR", "resources": [], "resource_count": 0}
            # The new planner is intentionally partial, so no completeness upgrade.
        print(f"[IMPACT] {address}: {record['impact']['status']}", flush=True)
        results.append(record)

    return results



def summarize_sg_impacts(records: list[dict]) -> dict[str, int]:
    """
    Summarize SG changes with descriptive DynamoDB field names.

    Counts change records, not unique AWS security groups.
    """

    summary = {
        "total_sg_change_records": len(records),
        "whole_sg_changes": 0,
        "whole_sg_lifecycle_changes": 0,
        "ingress_rule_changes": 0,
        "egress_rule_changes": 0,
        "resolved_rule_impacts": 0,
        "unresolved_rule_impacts": 0,
        "context_analysis_errors": 0,
        "incomplete_context_assessments": 0,
        "not_assessed_changes": 0,
        "not_applicable_changes": 0,
    }

    for record in records:
        resource_type = record.get("resource_type")
        direction = record.get("direction")
        impact = record.get("impact") or {}
        status = impact.get("status", "NOT_ASSESSED")

        if resource_type == "aws_security_group":
            summary["whole_sg_changes"] += 1

        if status == "LIFECYCLE_CHANGE":
            summary["whole_sg_lifecycle_changes"] += 1

        if resource_type in STANDALONE_RULE_TYPES:
            if direction == "ingress":
                summary["ingress_rule_changes"] += 1
            elif direction == "egress":
                summary["egress_rule_changes"] += 1

            if status == "RESOLVED":
                summary["resolved_rule_impacts"] += 1
            elif status == "UNRESOLVED":
                summary["unresolved_rule_impacts"] += 1

        if status == "CONTEXT_ERROR":
            summary["context_analysis_errors"] += 1

        if status == "NOT_ASSESSED":
            summary["not_assessed_changes"] += 1

        if status == "NOT_APPLICABLE":
            summary["not_applicable_changes"] += 1

        if impact.get("context_complete") is not True:
            summary["incomplete_context_assessments"] += 1

    return summary

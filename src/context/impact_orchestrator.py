"""Independent classification and best-effort security-group impact discovery.

The impact analysis never changes risk scores or deployment decisions.
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


def _lifecycle_action(actions: list[str]) -> str:
    """Normalize Terraform whole-SG actions into reporting labels."""
    if "create" in actions and "delete" in actions:
        return "REPLACE"
    if actions == ["create"]:
        return "CREATE"
    if actions == ["delete"]:
        return "DELETE"
    if actions == ["update"]:
        return "UPDATE"
    return "OTHER"


def analyze_all_sg_changes(
    plan: dict[str, Any],
    region: str = "ap-southeast-2",
    resource_collector: Callable | None = None,
) -> list[dict[str, Any]]:
    """Analyze detected SG changes independently of risk scoring.

    Whole-SG create/delete/replace operations produce one lifecycle record,
    rather than additional duplicate inline-ingress/egress records.
    In-place changes retain any distinct inline-rule records.

    Context status RESOLVED does not mean full network reachability was assessed.
    """
    changes = detect_security_group_changes(plan)

    # For whole-SG create/delete/replace, suppress redundant inline records.
    lifecycle_addresses: set[str] = set()
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
            actions = (terraform_change or {}).get("change", {}).get("actions", [])
            if "create" in actions or "delete" in actions:
                lifecycle_addresses.add(address)

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

        # This block MUST stay inside the for-loop. Only whole-SG records
        # get normalized lifecycle actions; rule classifications are unchanged.
        if (
            resource_type == "aws_security_group"
            and change.get("classification") == "LIFECYCLE_CHANGE"
        ):
            record["lifecycle_action"] = _lifecycle_action(
                change.get("terraform_actions", [])
            )

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
                print(f"[IMPACT] ERROR {address}: {error}", flush=True)
                record["impact"] = {
                    "status": "CONTEXT_ERROR",
                    "context_complete": False,
                    "existing_dependencies": None,
                    "planned_dependencies": None,
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

        # Standalone SG rules also receive planned Terraform EC2/ENI context.
        # This deliberately does not upgrade context_complete to True.
        if resource_type in STANDALONE_RULE_TYPES:
            impact = record["impact"]
            try:
                planned = find_planned_dependencies(
                    plan,
                    security_group_id=(
                        impact.get("security_group_id")
                        or change.get("security_group_id")
                    ),
                    security_group_address=impact.get("security_group_address"),
                )
                impact["planned_dependencies"] = planned
                print(
                    f"[PLANNED-IMPACT] {address}: "
                    f"{planned['resource_count']} matched resources",
                    flush=True,
                )
            except Exception as error:
                print(f"[PLANNED-IMPACT] ERROR {address}: {error}", flush=True)
                impact["planned_dependencies"] = {
                    "status": "ERROR",
                    "resources": [],
                    "resource_count": 0,
                }

        print(f"[IMPACT] {address}: {record['impact']['status']}", flush=True)
        results.append(record)

    if changes and not results:
        raise RuntimeError("SG impact processing produced no records")

    print(f"[IMPACT] Completed {len(results)} records", flush=True)
    return results


def summarize_sg_impacts(records: list[dict]) -> dict[str, int]:
    """Summarize impact records (not unique AWS security groups)."""
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

"""Stage 3D: independent, read-only route assessment for DynamoDB reporting.

This module never mutates AWS, risk findings, or deployment decisions.
"""
from __future__ import annotations

from typing import Any, Callable

from src.analyzers.route_changes import detect_route_changes
from src.context.route_impact import assess_route_change
from src.context.route_association_impact import assess_route_table_association
from src.context.route_plan_conflicts import association_plan_conflicts


def analyze_route_impacts(
    plan: dict[str, Any],
    *,
    region: str = "ap-southeast-2",
    assessor: Callable[..., dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return a record for every detected route change, even on discovery failure."""
    run_assessment = assessor or assess_route_change
    records: list[dict[str, Any]] = []
    detected = detect_route_changes(plan)
    for change in detected:
        try:
            if assessor is None and change.get("resource_type") == "aws_route_table_association":
                impact = assess_route_table_association(change, region=region)
            else:
                impact = run_assessment(change, region=region)
        except Exception as error:
            impact = {
                "status": "CONTEXT_ERROR",
                "context_complete": False,
                "error_type": type(error).__name__,
                "message": "Route context discovery failed; no safety conclusion available",
            }
        if change.get("resource_type") == "aws_route_table_association":
            conflicts = association_plan_conflicts(change, detected)
            if conflicts["status"] == "POTENTIAL_CONFLICT":
                impact = dict(impact)
                impact["route_plan_conflicts"] = conflicts
                prior = impact.get("route_set_comparison")
                if prior is not None:
                    impact["route_set_comparison"] = {
                        "status": "INCOMPLETE",
                        "reason": "Simultaneous route changes may alter the proposed route set",
                        "snapshot_comparison": prior,
                        "context_complete": False,
                    }
                impact["context_complete"] = False
                impact["status"] = "INCOMPLETE" if impact.get("status") not in {"CONTEXT_ERROR", "NOT_ASSESSED"} else impact.get("status")
        records.append({"change": change, "impact": impact})
    return records


def summarize_route_impacts(records: list[dict[str, Any]]) -> dict[str, int]:
    summary = {
        "total_route_changes": len(records),
        "assessed_route_changes": 0,
        "not_assessed_route_changes": 0,
        "incomplete_route_changes": 0,
        "route_context_errors": 0,
    }
    for record in records:
        impact = record.get("impact") or {}
        status = impact.get("status")
        if status == "CONTEXT_ERROR":
            summary["route_context_errors"] += 1
        if status == "NOT_ASSESSED":
            summary["not_assessed_route_changes"] += 1
        elif status != "CONTEXT_ERROR":
            summary["assessed_route_changes"] += 1
        if impact.get("context_complete") is not True:
            summary["incomplete_route_changes"] += 1
    return summary


def sanitize_route_impacts(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Bound DynamoDB evidence: retain useful counts and candidate routes, not ENI inventory."""
    output = []
    for record in records:
        change, impact = record["change"], record["impact"]
        context = impact.get("dependency_discovery") or {}
        output.append({
            "resource": change.get("resource"),
            "resource_type": change.get("resource_type"),
            "lifecycle_action": change.get("lifecycle_action"),
            "terraform_actions": change.get("terraform_actions", []),
            "impact": {
                "status": impact.get("status", "INCOMPLETE"),
                "context_complete": impact.get("context_complete", False),
                "route_table_id": impact.get("route_table_id"),
                "destination_before": impact.get("destination_before"),
                "destination_after": impact.get("destination_after"),
                "target_before": impact.get("target_before", {}),
                "target_after": impact.get("target_after", {}),
                "route_selection": impact.get("route_selection"),
                "potential_impact": impact.get("potential_impact"),
                "association_transition": impact.get("association_transition"),
                "route_set_comparison": impact.get("route_set_comparison"),
                "route_plan_conflicts": impact.get("route_plan_conflicts"),
                "subnet_id": impact.get("subnet_id"),
                "reason": impact.get("reason"),
                "error_type": impact.get("error_type"),
                "dependency_discovery": {
                    "status": context.get("status"),
                    "vpc_id": context.get("vpc_id"),
                    "route_table_id": context.get("route_table_id"),
                    "is_main_route_table": context.get("is_main_route_table"),
                    "affected_subnet_count": context.get("affected_subnet_count"),
                    "explicit_subnet_count": context.get("explicit_subnet_count"),
                    "implicit_subnet_count": context.get("implicit_subnet_count"),
                    "network_interface_count": context.get("network_interface_count"),
                },
            },
        })
    return output

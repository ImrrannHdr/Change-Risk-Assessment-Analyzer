"""Stage 2B: read-only, dependency-aware SG rule lifecycle assessment.

Combines Stage 1B configured-permission differences with the existing
blast-radius investigator. Does NOT assert traffic reachability or change
risk scores, IAM permissions, or AWS resources.
"""
from __future__ import annotations

from typing import Any, Callable

from src.context.sg_rule_delta import RULE_TYPES, analyze_sg_permission_deltas
from src.context.blast_radius import analyze_security_group_impact
from src.context.planned_sg_dependencies import find_planned_dependencies


def _dependency_count(impact: dict[str, Any], field: str) -> int | None:
    deps = impact.get(field)
    if not isinstance(deps, dict):
        return None
    key = "network_interface_count" if field == "existing_dependencies" else "resource_count"
    value = deps.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _assessment(delta: dict[str, Any], impact: dict[str, Any]) -> dict[str, Any]:
    """Produce cautious, actionable statements based on observed evidence."""
    effect = delta["permission_effect"]
    action = delta["lifecycle_action"]
    existing = _dependency_count(impact, "existing_dependencies")
    planned = _dependency_count(impact, "planned_dependencies")
    status = impact.get("status", "NOT_ASSESSED")
    incomplete = not delta["permission_comparison_complete"]
    added = delta["added_permissions"]
    removed = delta["removed_permissions"]
    if action == "DELETE":
        statement = "Removal of an SG rule may restrict new permitted traffic to workloads using the affected SG."
    elif action == "REPLACE":
        statement = "Replacement removes old configured permissions and adds new ones; traffic may be restricted or expanded."
    elif action == "UPDATE":
        statement = "Rule update may alter permitted traffic for workloads using the affected SG."
    elif action == "CREATE":
        statement = "New rule permissions may expand permitted traffic for workloads using the affected SG."
    else:
        statement = "SG rule lifecycle change requires review."
    if effect == "UNCHANGED":
        statement = "No configured permission delta identified; metadata or non-permission fields may have changed."
    elif effect == "UNKNOWN":
        statement = "Permission effect cannot be determined reliably from the available Terraform plan."
    elif effect == "EXPAND":
        statement = "Configured permissions are added; effective reachability is not established."
    elif effect == "RESTRICT":
        statement = "Configured permissions are removed; connection interruption is not established."
    elif effect == "MIXED":
        statement = "Configured permissions are both added and removed; assess both expansion and restriction."
    if incomplete:
        statement += " Some permission inputs are unknown."

    if status in {"CONTEXT_ERROR", "UNRESOLVED", "NOT_ASSESSED"}:
        category = "DEPENDENCY_INVESTIGATION_INCOMPLETE"
    elif existing is not None and existing > 0:
        category = "EXISTING_ENI_ASSOCIATIONS_REQUIRE_REVIEW"
    elif planned is not None and planned > 0:
        category = "PLANNED_WORKLOAD_DEPENDENCIES_REQUIRE_REVIEW"
    elif existing == 0 and planned == 0:
        category = "NO_SUPPORTED_DEPENDENCIES_OBSERVED"
    else:
        category = "DEPENDENCY_SCOPE_UNKNOWN"

    return {
        "status": "PARTIAL" if category != "DEPENDENCY_INVESTIGATION_INCOMPLETE" else "INCOMPLETE",
        "impact_category": category,
        "lifecycle_action": action,
        "permission_effect": effect,
        "added_permission_count": len(added),
        "removed_permission_count": len(removed),
        "permission_comparison_complete": not incomplete,
        "existing_eni_count": existing,
        "planned_resource_count": planned,
        "context_complete": False,
        "potential_impact": statement,
        "limitations": (
            "Existing discovery covers supported EC2/ENI associations only; "
            "Terraform planned-dependency inspection is partial. No route/NACL, "
            "SG rule union, connection tracking, or actual reachability determination."
        ),
    }


def analyze_sg_rule_lifecycle_impacts(
    plan: dict[str, Any],
    region: str = "ap-southeast-2",
    resource_collector: Callable | None = None,
) -> list[dict[str, Any]]:
    """Return one evidence record per *standalone* SG rule change.

    Original blast-radius API and its injected collector contract are preserved.
    Errors are surfaced per resource, never silently treated as no dependencies.
    Whole SG/inline rules remain handled separately by sg_lifecycle.py.
    """
    deltas = analyze_sg_permission_deltas(plan)
    results: list[dict[str, Any]] = []
    for delta in deltas:
        if delta["resource_type"] not in RULE_TYPES:
            continue
        address = delta["resource"]
        try:
            impact = analyze_security_group_impact(
                plan=plan,
                rule_address=address,
                region=region,
                resource_collector=resource_collector,
            )
            if not isinstance(impact, dict):
                raise TypeError("Blast-radius investigator must return a dictionary")
        except Exception as error:
            impact = {
                "status": "CONTEXT_ERROR",
                "context_complete": False,
                "security_group_id": None,
                "security_group_address": None,
                "existing_dependencies": None,
                "planned_dependencies": None,
                "message": f"Blast-radius investigation failed: {type(error).__name__}",
            }

        # Match existing orchestrator's enrichment step. Do not replace a more
        # informative context error with an apparent clean dependency count.
        if impact.get("status") != "CONTEXT_ERROR":
            try:
                impact["planned_dependencies"] = find_planned_dependencies(
                    plan,
                    security_group_id=impact.get("security_group_id"),
                    security_group_address=impact.get("security_group_address"),
                )
            except Exception as error:
                impact["planned_dependencies"] = {
                    "status": "ERROR", "resources": [], "resource_count": 0,
                    "unknown_candidates": [],
                    "message": f"Planned dependency investigation failed: {type(error).__name__}",
                }
        results.append({
            "resource": address,
            "resource_type": delta["resource_type"],
            "terraform_actions": delta["terraform_actions"],
            "lifecycle_action": delta["lifecycle_action"],
            "permission_delta": delta,
            "impact": impact,
            "assessment": _assessment(delta, impact),
        })
    return results

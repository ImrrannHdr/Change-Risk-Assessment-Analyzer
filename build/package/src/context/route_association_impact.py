"""Stage 3E: conservative, read-only assessment of subnet route-table associations.

Supports existing aws_route_table_association DELETE/UPDATE/REPLACE and
CREATE with already-known route table ID. No AWS mutations. Not reachability proof.
"""
from __future__ import annotations
from typing import Any, Callable
from src.context.route_context import discover_route_table_context
from src.context.route_set_comparison import compare_route_sets


def assess_route_table_association(
    change: dict[str, Any], *, region: str = "ap-southeast-2",
    discover: Callable[..., dict[str, Any]] = discover_route_table_context,
) -> dict[str, Any]:
    if change.get("resource_type") != "aws_route_table_association":
        return {"status": "NOT_ASSESSED", "context_complete": False,
                "reason": "Only subnet route-table associations supported; main/gateway associations excluded"}
    before, after = change.get("before") or {}, change.get("after") or {}
    action = change.get("lifecycle_action")
    old_sid = before.get("subnet_id")
    new_sid = after.get("subnet_id")
    subnet_id = old_sid or new_sid
    if before.get("gateway_id") or after.get("gateway_id"):
        return {"status": "NOT_ASSESSED", "context_complete": False,
                "reason": "Gateway/edge route-table association requires separate analysis"}
    if not isinstance(subnet_id, str) or not subnet_id.startswith("subnet-"):
        return {"status": "INCOMPLETE", "context_complete": False,
                "reason": "Subnet identity unavailable in Terraform plan"}
    if old_sid and new_sid and old_sid != new_sid:
        return {"status": "INCOMPLETE", "context_complete": False,
                "subnet_id": subnet_id, "reason": "Association changes subnet identity; assess each subnet separately"}
    old_rtb = before.get("route_table_id")
    new_rtb = after.get("route_table_id")
    known_rtb = old_rtb if isinstance(old_rtb, str) and old_rtb.startswith("rtb-") else new_rtb
    if not isinstance(known_rtb, str) or not known_rtb.startswith("rtb-"):
        return {"status": "INCOMPLETE", "context_complete": False,
                "subnet_id": subnet_id, "reason": "Route table identity unknown; AWS discovery skipped"}
    context = discover(known_rtb, region=region)
    current_association = next((x for x in context.get("affected_subnets", [])
                                if x.get("subnet_id") == subnet_id), None)
    # If looking at new table of a create, current association may be elsewhere:
    # This does not mean subnet absent from VPC; never infer a positive match.
    if action in {"DELETE", "UPDATE", "REPLACE"} and old_rtb == known_rtb and not current_association:
        return {"status": "INCOMPLETE", "context_complete": False,
                "subnet_id": subnet_id, "route_table_id": known_rtb,
                "reason": "Subnet not currently associated with plan's old route table; drift possible",
                "dependency_discovery": context}
    if action == "DELETE":
        target = context.get("main_route_table_id")
        target_kind = "IMPLICIT_MAIN"
    elif action in {"CREATE", "UPDATE", "REPLACE"}:
        target = new_rtb if isinstance(new_rtb, str) and new_rtb.startswith("rtb-") else None
        target_kind = "EXPLICIT" if target else "UNKNOWN"
    else:
        return {"status": "NOT_ASSESSED", "context_complete": False,
                "reason": "Unsupported association lifecycle action"}
    route_set_comparison = {"status": "INCOMPLETE", "reason": "Both existing route-table IDs required"}
    if isinstance(old_rtb, str) and old_rtb.startswith("rtb-") and isinstance(target, str) and target.startswith("rtb-"):
        if old_rtb == target:
            route_set_comparison = {"status": "CANDIDATE_ONLY", "changed_destination_count": 0, "changes": [], "context_complete": False, "note": "Same route table ID; simultaneous plan changes not modelled"}
        else:
            target_context = discover(target, region=region)
            if target_context.get("vpc_id") != context.get("vpc_id") or target_context.get("status") != "RESOLVED":
                route_set_comparison = {"status": "INCOMPLETE", "reason": "Destination table missing or VPC mismatch"}
            else:
                route_set_comparison = compare_route_sets(context.get("routes") or [], target_context.get("routes") or [])
    transition = {
        "subnet_id": subnet_id,
        "before_route_table_id": old_rtb if isinstance(old_rtb, str) else None,
        "before_association_type": current_association.get("association_type") if current_association else None,
        "after_route_table_id": target,
        "after_association_type": target_kind,
    }
    return {
        "status": "PARTIAL", "context_complete": False,
        "resource": change.get("resource"), "action": action,
        "route_table_id": known_rtb, "subnet_id": subnet_id,
        "association_transition": transition,
        "route_set_comparison": route_set_comparison,
        "dependency_discovery": context,
        "potential_impact": "Subnet routing-table selection may change; route-by-route connectivity not assessed",
        "reason": ("New route table ID is unknown until apply" if target is None else None),
        "limitations": ["Current AWS associations may drift", "Simultaneous planned route changes not reconciled",
                        "No TGW/SG/NACL/return-path or application-flow proof"],
    }

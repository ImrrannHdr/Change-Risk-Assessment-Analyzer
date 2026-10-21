"""Stage 3A: read-only Terraform route and route-table change detection.

Emits change evidence, not effective reachability or risk decisions.
"""
from __future__ import annotations

from typing import Any

ROUTE_TYPES = {"aws_route", "aws_route_table", "aws_route_table_association", "aws_main_route_table_association"}
DESTINATION_KEYS = ("destination_cidr_block", "destination_ipv6_cidr_block", "destination_prefix_list_id", "cidr_block", "ipv6_cidr_block")
TARGET_KEYS = ("transit_gateway_id", "nat_gateway_id", "gateway_id", "vpc_peering_connection_id", "network_interface_id", "instance_id", "egress_only_gateway_id", "local_gateway_id", "carrier_gateway_id", "vpc_endpoint_id", "core_network_arn")


def _action(actions: list[str]) -> str:
    if "create" in actions and "delete" in actions:
        return "REPLACE"
    if actions == ["create"]:
        return "CREATE"
    if actions == ["delete"]:
        return "DELETE"
    if actions == ["update"]:
        return "UPDATE"
    return "OTHER"


def _route_fields(value: dict[str, Any] | None) -> dict[str, Any]:
    value = value if isinstance(value, dict) else {}
    dest = {key: value[key] for key in DESTINATION_KEYS if value.get(key) is not None}
    target = {key: value[key] for key in TARGET_KEYS if value.get(key) is not None}
    return {"destinations": dest, "targets": target, "route_table_id": value.get("route_table_id")}


def _association_fields(value: dict[str, Any] | None) -> dict[str, Any]:
    value = value if isinstance(value, dict) else {}
    return {key: value.get(key) for key in ("route_table_id", "subnet_id", "gateway_id", "vpc_id")}


def _inline_routes(value: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if not isinstance(value, dict):
        return None
    routes = value.get("route")
    if routes is None:
        return None
    if not isinstance(routes, list):
        return None
    return [_route_fields(route) for route in routes if isinstance(route, dict)]


def _route_key(route: dict[str, Any]) -> tuple:
    return tuple(sorted(route["destinations"].items()))


def _diff_inline(before: list[dict[str, Any]] | None, after: list[dict[str, Any]] | None) -> dict[str, Any]:
    if before is None or after is None:
        return {"status": "INCOMPLETE", "added": [], "removed": [], "modified": []}
    old = {_route_key(x): x for x in before}
    new = {_route_key(x): x for x in after}
    added = [new[k] for k in sorted(new.keys() - old.keys())]
    removed = [old[k] for k in sorted(old.keys() - new.keys())]
    modified = [{"before": old[k], "after": new[k]} for k in sorted(old.keys() & new.keys()) if old[k] != new[k]]
    return {"status": "COMPARED", "added": added, "removed": removed, "modified": modified}


def detect_route_changes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    """Return one evidence record per changed resource; no AWS API calls."""
    records: list[dict[str, Any]] = []
    for resource in plan.get("resource_changes", []):
        if not isinstance(resource, dict) or resource.get("type") not in ROUTE_TYPES:
            continue
        change = resource.get("change") or {}
        actions = change.get("actions") or []
        if actions == ["no-op"] or not actions:
            continue
        before = change.get("before")
        after = change.get("after")
        resource_type = resource["type"]
        record: dict[str, Any] = {
            "resource": resource.get("address"),
            "resource_type": resource_type,
            "terraform_actions": actions,
            "lifecycle_action": _action(actions),
            "analysis_scope": "PLAN_ONLY",
            "context_complete": False,
            "unknown_paths": list((change.get("after_unknown") or {}).keys()),
        }
        if resource_type == "aws_route":
            record["before"] = _route_fields(before)
            record["after"] = _route_fields(after)
        elif resource_type == "aws_route_table":
            record["route_table_id_before"] = (before or {}).get("id")
            record["route_table_id_after"] = (after or {}).get("id")
            record["vpc_id_before"] = (before or {}).get("vpc_id")
            record["vpc_id_after"] = (after or {}).get("vpc_id")
            record["inline_route_changes"] = _diff_inline(_inline_routes(before), _inline_routes(after))
            if (change.get("after_unknown") or {}).get("route"):
                record["inline_route_changes"]["status"] = "INCOMPLETE"
        else:
            record["before"] = _association_fields(before)
            record["after"] = _association_fields(after)
            record["association_kind"] = "MAIN" if resource_type == "aws_main_route_table_association" else "SUBNET_OR_GATEWAY"
        records.append(record)
    return records

"""Read-only Terraform SG permission deltas, independent of risk scoring.

Supports standalone SG rules (new and legacy) and inline SG rules.
The output describes *configured permission differences*, not proven connectivity.
"""
from __future__ import annotations

from typing import Any

RULE_TYPES = {
    "aws_vpc_security_group_ingress_rule": "ingress",
    "aws_vpc_security_group_egress_rule": "egress",
    "aws_security_group_rule": None,
}


def lifecycle_action(actions: list[str]) -> str:
    if "create" in actions and "delete" in actions:
        return "REPLACE"
    return {
        ("create",): "CREATE",
        ("delete",): "DELETE",
        ("update",): "UPDATE",
        ("no-op",): "NO_OP",
    }.get(tuple(actions), "OTHER")


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _targets(rule: dict[str, Any]) -> list[tuple[str, str]]:
    """Represent CIDRs, prefix lists, and SG refs without conflating them."""
    found: set[tuple[str, str]] = set()
    for attr, label in (
        ("cidr_ipv4", "ipv4"), ("cidr_ipv6", "ipv6"),
        ("referenced_security_group_id", "sg"), ("prefix_list_id", "prefix_list"),
    ):
        val = rule.get(attr)
        if isinstance(val, str) and val:
            found.add((label, val))
    for attr, label in (
        ("cidr_blocks", "ipv4"), ("ipv6_cidr_blocks", "ipv6"),
        ("prefix_list_ids", "prefix_list"), ("security_groups", "sg"),
    ):
        found.update((label, x) for x in _list(rule.get(attr)) if isinstance(x, str) and x)
    return sorted(found)


def _normalize(rule: dict[str, Any], direction: str) -> list[dict[str, Any]]:
    protocol = str(rule.get("ip_protocol", rule.get("protocol", ""))).lower()
    from_port = rule.get("from_port")
    to_port = rule.get("to_port")
    # Terraform supports '-1' (all protocols); ports are irrelevant for this protocol.
    if protocol in {"-1", "all"}:
        from_port = to_port = None
    # A rule may have an unknown destination in a planned create.
    targets = _targets(rule)
    if not targets:
        return []
    return [
        {"direction": direction, "protocol": protocol,
         "from_port": from_port, "to_port": to_port,
         "target_type": kind, "target": value}
        for kind, value in targets
    ]


def _permissions(resource_type: str, values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, dict):
        return []
    rules: list[dict[str, Any]] = []
    if resource_type == "aws_security_group":
        for direction in ("ingress", "egress"):
            for rule in _list(values.get(direction)):
                if isinstance(rule, dict):
                    rules.extend(_normalize(rule, direction))
    else:
        direction = RULE_TYPES.get(resource_type)
        if direction is None:
            direction = values.get("type")
        if direction in {"ingress", "egress"}:
            rules.extend(_normalize(values, direction))
    return rules


def _key(rule: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(rule.get(field) for field in (
        "direction", "protocol", "from_port", "to_port", "target_type", "target"
    ))


def _has_unknown(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, list):
        return any(_has_unknown(v) for v in value)
    if isinstance(value, dict):
        return any(_has_unknown(v) for v in value.values())
    return False


def analyze_sg_permission_deltas(plan: dict[str, Any]) -> list[dict[str, Any]]:
    """Return one record per changed SG/rule, using resource_changes only.

    An in-place rule replacement is reported as removed+added permissions.
    Unknown before/after permission fields make the assessment incomplete.
    A 'RESTRICT' or 'EXPAND' label means configured permissions only.
    """
    records = []
    for resource in plan.get("resource_changes") or []:
        resource_type = resource.get("type")
        if resource_type not in RULE_TYPES and resource_type != "aws_security_group":
            continue
        change = resource.get("change") or {}
        actions = change.get("actions") or []
        action = lifecycle_action(actions)
        if action == "NO_OP" or not actions:
            continue
        before = _permissions(resource_type, change.get("before"))
        after = _permissions(resource_type, change.get("after"))
        before_map = {_key(item): item for item in before}
        after_map = {_key(item): item for item in after}
        added = [after_map[k] for k in sorted(after_map.keys() - before_map.keys(), key=str)]
        removed = [before_map[k] for k in sorted(before_map.keys() - after_map.keys(), key=str)]
        # `after_unknown` often contains IDs and timestamps, so inspect only rule inputs.
        markers = change.get("after_unknown") or {}
        if resource_type == "aws_security_group":
            unknown = any(_has_unknown(markers.get(x)) for x in ("ingress", "egress"))
        else:
            unknown = any(_has_unknown(markers.get(x)) for x in (
                "ip_protocol", "protocol", "from_port", "to_port", "cidr_ipv4",
                "cidr_ipv6", "cidr_blocks", "ipv6_cidr_blocks", "prefix_list_id",
                "prefix_list_ids", "referenced_security_group_id", "security_groups", "type"
            ))
        if added and removed:
            effect = "MIXED"
        elif added:
            effect = "EXPAND"
        elif removed:
            effect = "RESTRICT"
        else:
            effect = "UNKNOWN" if unknown else "UNCHANGED"
        records.append({
            "resource": resource.get("address"),
            "resource_type": resource_type,
            "terraform_actions": actions,
            "lifecycle_action": action,
            "permission_effect": effect,
            "added_permissions": added,
            "removed_permissions": removed,
            "context_complete": False,
            "permission_comparison_complete": not unknown,
            "message": "Permission delta only; effective reachability and dependencies not assessed.",
        })
    return records

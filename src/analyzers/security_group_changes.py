
import json
from typing import Any


SG_TYPES = {
    "aws_security_group",
    "aws_security_group_rule",
    "aws_vpc_security_group_ingress_rule",
    "aws_vpc_security_group_egress_rule",
}

NETWORK_FIELDS = {
    "security_group_id",
    "type",
    "ip_protocol",
    "protocol",
    "from_port",
    "to_port",
    "cidr_ipv4",
    "cidr_ipv6",
    "cidr_blocks",
    "ipv6_cidr_blocks",
    "prefix_list_id",
    "prefix_list_ids",
    "referenced_security_group_id",
    "source_security_group_id",
    "self",
    "ingress",
    "egress",
}

RULE_FIELDS = NETWORK_FIELDS - {"ingress", "egress"}


def _action_type(actions: list[str]) -> str:
    mapping = {
        ("create",): "ADDED",
        ("delete",): "REMOVED",
        ("update",): "MODIFIED",
        ("delete", "create"): "REPLACED",
        ("create", "delete"): "REPLACED",
    }

    return mapping.get(tuple(actions), "UNKNOWN")


def _paths(value: Any, prefix: str = "") -> list[str]:
    paths = []

    if value is True:
        return [prefix or "<root>"]

    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            paths.extend(_paths(child, path))

    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.extend(
                _paths(child, f"{prefix}[{index}]")
            )

    return paths


def _relevant(paths: list[str]) -> list[str]:
    return [
        path
        for path in paths
        if path.split(".")[0].split("[")[0]
        in NETWORK_FIELDS
    ]


def _network_values(rule: dict) -> dict:
    return {
        key: rule[key]
        for key in RULE_FIELDS
        if key in rule
    }


def _rule_key(rule: dict) -> str:
    return json.dumps(
        _network_values(rule),
        sort_keys=True,
        default=str,
    )


def _inline_difference(before: list, after: list):
    old = {
        _rule_key(rule): rule
        for rule in before
        if isinstance(rule, dict)
    }

    new = {
        _rule_key(rule): rule
        for rule in after
        if isinstance(rule, dict)
    }

    added = [
        new[key] for key in sorted(new.keys() - old.keys())
    ]

    removed = [
        old[key] for key in sorted(old.keys() - new.keys())
    ]

    return added, removed


def _direction(resource_type, before, after):
    if resource_type == "aws_vpc_security_group_ingress_rule":
        return "ingress"

    if resource_type == "aws_vpc_security_group_egress_rule":
        return "egress"

    old = before.get("type")
    new = after.get("type")

    if old and new and old != new:
        return "changed"

    return new or old or "unknown"


def _impact(classification, direction, incomplete):
    if incomplete:
        return (
            "Network change is potentially incomplete. "
            "Unknown or sensitive values require investigation."
        )

    impacts = {
        "ADDED": f"{direction} access may expand.",
        "REMOVED": f"{direction} access may decrease.",
        "MODIFIED": (
            f"{direction} permissions changed. "
            "Effective before/after access requires comparison."
        ),
        "METADATA_ONLY": (
            "No network permission change identified "
            "from the compared attributes."
        ),
        "REPLACED": (
            "Resource replacement may affect connectivity "
            "during its lifecycle."
        ),
    }

    return impacts.get(
        classification,
        "Impact requires investigation.",
    )


def detect_security_group_changes(
    plan: dict[str, Any],
) -> list[dict[str, Any]]:

    results = []

    for resource in plan.get("resource_changes", []):
        if resource.get("mode", "managed") != "managed":
            continue

        resource_type = resource.get("type")

        if resource_type not in SG_TYPES:
            continue

        change = resource.get("change") or {}
        actions = change.get("actions") or []

        if not actions or actions == ["no-op"]:
            continue

        before = change.get("before") or {}
        after = change.get("after") or {}

        unknown = _relevant(
            _paths(change.get("after_unknown") or {})
        )

        sensitive = _relevant(
            _paths(change.get("before_sensitive") or {})
            + _paths(change.get("after_sensitive") or {})
        )

        incomplete = bool(unknown or sensitive)

        action_type = _action_type(actions)
        address = resource.get("address")

        common = {
            "resource": address,
            "resource_type": resource_type,
            "terraform_actions": actions,
            "unknown_paths": unknown,
            "sensitive_paths": sensitive,
            "replace_paths": change.get("replace_paths", []),
        }

        if resource_type == "aws_security_group":

            for direction in ("ingress", "egress"):

                old_rules = before.get(direction) or []
                new_rules = after.get(direction) or []

                direction_incomplete = any(
                    path == direction
                    or path.startswith(direction + ".")
                    or path.startswith(direction + "[")
                    for path in unknown + sensitive
                )

                malformed = not (
                    isinstance(old_rules, list)
                    and isinstance(new_rules, list)
                )

                if malformed:
                    direction_incomplete = True
                    old_rules = []
                    new_rules = []

                added, removed = _inline_difference(
                    old_rules, new_rules
                )

                if not added and not removed and not direction_incomplete:
                    continue

                if action_type == "REPLACED":
                    classification = "REPLACED"
                elif added and removed:
                    classification = "MODIFIED"
                elif added:
                    classification = "ADDED"
                elif removed:
                    classification = "REMOVED"
                else:
                    classification = "UNKNOWN"

                results.append({
                    **common,
                    "security_group_address": address,
                    "security_group_id": (
                        before.get("id") or after.get("id")
                    ),
                    "direction": direction,
                    "classification": classification,
                    "added_rules": added,
                    "removed_rules": removed,
                    "analysis_complete": not direction_incomplete,
                    "possible_impact": _impact(
                        classification,
                        direction,
                        direction_incomplete,
                    ),
                    "comparison_method": "inline_rule_set",
                })

            if action_type in {
                "ADDED", "REMOVED", "REPLACED"
            }:
                results.append({
                    **common,
                    "security_group_address": address,
                    "security_group_id": (
                        before.get("id") or after.get("id")
                    ),
                    "direction": "both",
                    "classification": "LIFECYCLE_CHANGE",
                    "lifecycle_action": action_type,
                    "analysis_complete": False,
                    "possible_impact": (
                        "Security group lifecycle and "
                        "resource attachments require assessment."
                    ),
                })

            continue

        # Standalone rule
        direction = _direction(
            resource_type, before, after
        )

        old_permissions = _network_values(before)
        new_permissions = _network_values(after)

        if (
            action_type == "MODIFIED"
            and old_permissions == new_permissions
            and not incomplete
        ):
            classification = "METADATA_ONLY"
        else:
            classification = action_type

        # Do not downgrade a known Terraform action to
        # UNKNOWN merely because an attribute is computed.

        results.append({
            **common,
            "security_group_id": (
                after.get("security_group_id")
                or before.get("security_group_id")
            ),
            "direction": direction,
            "classification": classification,
            "before": before or None,
            "after": after or None,
            "analysis_complete": (
                not incomplete
                and classification != "REPLACED"
                and classification != "UNKNOWN"
            ),
            "possible_impact": _impact(
                classification,
                direction,
                incomplete,
            ),
            "comparison_method": "resource_before_after",
        })

    return results

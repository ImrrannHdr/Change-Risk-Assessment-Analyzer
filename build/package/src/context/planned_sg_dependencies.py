"""Conservative, read-only planned dependencies for SG rules.

MVP scope: root-module aws_instance.vpc_security_group_ids and
aws_network_interface.security_groups, only resources with planned changes.
Never infer use of an SG from membership in the same VPC.
"""
from __future__ import annotations

from typing import Any

FIELDS = {
    "aws_instance": "vpc_security_group_ids",
    "aws_network_interface": "security_groups",
}


def _references(plan: dict[str, Any], address: str, field: str) -> list[str]:
    root = (plan.get("configuration") or {}).get("root_module") or {}
    for resource in root.get("resources") or []:
        if resource.get("address") == address:
            expr = (resource.get("expressions") or {}).get(field) or {}
            return expr.get("references") or []
    return []


def _sg_addresses(plan: dict[str, Any], sg_id: str | None, sg_address: str | None) -> set[str]:
    addresses = {sg_address} if sg_address else set()
    if not sg_id:
        return addresses
    for resource in plan.get("resource_changes") or []:
        if resource.get("type") != "aws_security_group":
            continue
        change = resource.get("change") or {}
        values = (change.get("after") or {}, change.get("before") or {})
        if any(v.get("id") == sg_id for v in values):
            addresses.add(resource["address"])
    # Also support unchanged SGs represented in planned_values.
    for resource in ((plan.get("planned_values") or {}).get("root_module") or {}).get("resources") or []:
        if resource.get("type") == "aws_security_group" and (resource.get("values") or {}).get("id") == sg_id:
            addresses.add(resource["address"])
    return addresses

def _references_different_explicit_sg(
    refs: list[str],
    target_addresses: set[str],
) -> bool:
    if not refs:
        return False

    referenced_sgs = set()

    for ref in refs:
        parts = ref.split(".")

        if len(parts) < 2 or parts[0] != "aws_security_group":
            return False

        referenced_sgs.add(".".join(parts[:2]))

    return bool(referenced_sgs) and referenced_sgs.isdisjoint(
        target_addresses
    )


def find_planned_dependencies(
    plan: dict[str, Any],
    security_group_id: str | None = None,
    security_group_address: str | None = None,
) -> dict[str, Any]:
    """Inspect planned EC2/ENI changes for matching SG IDs/references.

    `unknown_candidates` are never counted as confirmed impacted resources.
    This MVP does not parse nested modules, provider defaults, or dynamic expressions.
    """
    addresses = _sg_addresses(plan, security_group_id, security_group_address)
    matched: list[dict[str, Any]] = []
    unknown_candidates: list[str] = []
    for resource in plan.get("resource_changes") or []:
        kind = resource.get("type")
        if kind not in FIELDS:
            continue
        change = resource.get("change") or {}
        actions = change.get("actions") or []
        if actions == ["no-op"] or not actions:
            continue
        field = FIELDS[kind]
        after = change.get("after") or {}
        before = change.get("before") or {}
        values = before if actions == ["delete"] else after
        sg_ids = values.get(field) or []
        direct_match = bool(security_group_id and isinstance(sg_ids, list) and security_group_id in sg_ids)
        refs = _references(plan, resource.get("address", ""), field)
        ref_match = any(ref == address or ref.startswith(address + ".") for ref in refs for address in addresses)
        # References describe configuration, not necessarily the before side of a deletion.
        if actions == ["delete"]:
            ref_match = False
        if direct_match or ref_match:
            matched.append({
                "resource": resource.get("address"),
                "resource_type": kind,
                "actions": actions,
                "match_source": "plan_values" if direct_match else "terraform_reference",
            })
        elif (change.get("after_unknown") or {}).get(field):
    # Do not flag an unrelated SG when this EC2/ENI
    # explicitly references a different Terraform SG.
            if not _references_different_explicit_sg(refs, addresses):
                unknown_candidates.append(
                    resource.get("address", "")
                )
    return {
        "status": "PARTIAL",  # Root module and EC2/ENI only
        "resources": matched,
        "resource_count": len(matched),
        "unknown_candidates": unknown_candidates,
        "supported_resource_types": sorted(FIELDS),
        "matched_security_group_addresses": sorted(addresses),
    }
"""Read-only, conservative whole-security-group lifecycle impact assessment.

Stage 2A adds before/after EC2/ENI attachment transitions for SG DELETE and
REPLACE. This is evidence of dependencies, never proof of service downtime.
"""
from __future__ import annotations

from typing import Any, Callable

from src.context.planned_sg_dependencies import find_planned_dependencies,_has_unknown


ATTACHMENT_FIELDS = {
    "aws_instance": "vpc_security_group_ids",
    "aws_network_interface": "security_groups",
}


def _sg_id(values: Any) -> str | None:
    if not isinstance(values, dict):
        return None
    value = values.get("id")
    return value if isinstance(value, str) and value.startswith("sg-") else None


def _aws_associations(sg_id: str, region: str, collector: Callable | None) -> dict:
    """Return ENIs currently attached to sg_id; errors propagate to caller."""
    if collector is not None:
        return collector(security_group_id=sg_id, region=region)
    import boto3
    ec2 = boto3.client("ec2", region_name=region)
    enis = []
    paginator = ec2.get_paginator("describe_network_interfaces")
    for page in paginator.paginate(Filters=[{"Name": "group-id", "Values": [sg_id]}]):
        for eni in page.get("NetworkInterfaces", []):
            attachment = eni.get("Attachment") or {}
            association = eni.get("Association") or {}
            enis.append({
                "network_interface_id": eni["NetworkInterfaceId"],
                "instance_id": attachment.get("InstanceId"),
                "interface_type": eni.get("InterfaceType"),
                "description": eni.get("Description"),
                "public_ip": association.get("PublicIp"),
            })
    ids = sorted({eni["instance_id"] for eni in enis if eni.get("instance_id")})
    return {
        "ec2_instances": ids,
        "instance_count": len(ids),
        "network_interfaces": enis,
        "network_interface_count": len(enis),
        "public_ip_detected": any(bool(eni["public_ip"]) for eni in enis),
    }


def _reference_addresses(plan: dict[str, Any], address: str, field: str) -> set[str]:
    """Recognise root-module SG references in current/desired configuration."""
    root = ((plan.get("configuration") or {}).get("root_module") or {})
    for res in root.get("resources") or []:
        if res.get("address") != address:
            continue
        expression = ((res.get("expressions") or {}).get(field) or {})
        result = set()
        for ref in expression.get("references") or []:
            parts = ref.split(".")
            if len(parts) >= 2 and parts[0] == "aws_security_group":
                result.add(".".join(parts[:2]))
        return result
    return set()


def _planned_attachment_transitions(
    plan: dict[str, Any], old_id: str | None, sg_address: str, operation: str,
) -> dict[str, Any]:
    """Classify *changed* root-module EC2/ENI SG memberships.

    Current configuration refs are only applied to the after state. A new SG
    created during replacement usually has an unknown ID, so after references
    to the replaced Terraform address are used to detect planned migration.
    """
    transitions = []
    unknown_candidates = []
    for res in plan.get("resource_changes") or []:
        kind = res.get("type")
        if kind not in ATTACHMENT_FIELDS:
            continue
        change = res.get("change") or {}
        actions = change.get("actions") or []
        if not actions or actions == ["no-op"]:
            continue
        field = ATTACHMENT_FIELDS[kind]
        before = change.get("before") or {}
        after = change.get("after") or {}
        before_groups = before.get(field)
        after_groups = after.get(field)
        before_known = isinstance(before_groups, list)
        after_known = isinstance(after_groups, list)
        was_attached = bool(old_id and before_known and old_id in before_groups)
        after_has_old = bool(old_id and after_known and old_id in after_groups)
        after_refs = _reference_addresses(plan, res.get("address", ""), field)
        after_unknown = _has_unknown((change.get("after_unknown") or {}).get(field))
        # Only use refs for desired state, and never for pure deletion.
        targets_replacement = (
            "create" in actions or "update" in actions
        ) and operation == "REPLACE" and sg_address in after_refs
        if not (was_attached or after_has_old or targets_replacement):
            # Potentially relevant only if desired memberships are unknown and
            # we cannot establish which SG the reference targets.
            if after_unknown and not after_refs:
                unknown_candidates.append(res.get("address"))
            continue
        if was_attached and actions == ["delete"]:
            transition = "RESOURCE_DELETE_PLANNED"
        elif was_attached and after_has_old:
            transition = "OLD_SG_RETAINED_IN_PLAN"
        elif was_attached and targets_replacement:
            transition = "REATTACHMENT_TO_REPLACEMENT_PLANNED"
        elif was_attached and after_known and not after_unknown:
            transition = "OLD_SG_DETACHMENT_PLANNED"
        elif targets_replacement:
            transition = "REPLACEMENT_SG_ATTACHMENT_PLANNED"
        else:
            transition = "UNRESOLVED"
            unknown_candidates.append(res.get("address"))
        transitions.append({
            "resource": res.get("address"),
            "resource_type": kind,
            "actions": actions,
            "transition": transition,
            "before_has_old_sg": was_attached,
            "after_has_old_sg": after_has_old,
            "after_references_replacement": targets_replacement,
        })
    return {
        "status": "PARTIAL",
        "transitions": transitions,
        "transition_count": len(transitions),
        "unknown_candidates": sorted(set(unknown_candidates)),
        "scope": "Changed root-module EC2/ENI resources only",
    }


def analyze_sg_lifecycle(
    plan: dict[str, Any], sg_address: str, region: str = "ap-southeast-2",
    resource_collector: Callable | None = None,
) -> dict[str, Any]:
    """Investigate SG CREATE/UPDATE/DELETE/REPLACE without AWS mutations."""
    resource = next((r for r in plan.get("resource_changes") or []
                     if r.get("address") == sg_address
                     and r.get("type") == "aws_security_group"), None)
    if resource is None:
        return {
            "status": "NOT_ASSESSED", "context_complete": False,
            "message": "Whole-SG resource change not found in plan",
            "existing_dependencies": None, "planned_dependencies": None,
        }
    change = resource.get("change") or {}
    actions = change.get("actions") or []
    old_id = _sg_id(change.get("before"))
    new_id = None if _has_unknown((change.get("after_unknown") or {}).get("id")) else _sg_id(change.get("after"))
    operation = (
        "REPLACE" if "create" in actions and "delete" in actions else
        "DELETE" if actions == ["delete"] else
        "CREATE" if actions == ["create"] else
        "UPDATE" if actions == ["update"] else "OTHER"
    )
    errors = []
    aws_context = None
    if old_id and operation in {"DELETE", "REPLACE", "UPDATE"}:
        try:
            aws_context = _aws_associations(old_id, region, resource_collector)
        except Exception as error:
            errors.append(f"AWS lookup failed: {type(error).__name__}: {error}")
    try:
        planned = find_planned_dependencies(
            plan, security_group_id=new_id or old_id,
            security_group_address=sg_address,
        )
    except Exception as error:
        errors.append(f"Planned lookup failed: {type(error).__name__}: {error}")
        planned = None
    try:
        transitions = _planned_attachment_transitions(plan, old_id, sg_address, operation)
    except Exception as error:
        errors.append(f"Attachment transition analysis failed: {type(error).__name__}: {error}")
        transitions = None

    observed = (aws_context or {}).get("network_interface_count") if aws_context is not None else None
    if operation in {"DELETE", "REPLACE"}:
        if errors:
            impact_category = "INVESTIGATION_ERROR"
        elif observed is None:
            impact_category = "UNKNOWN_EXISTING_ASSOCIATIONS"
        elif observed > 0:
            impact_category = "EXISTING_ATTACHMENTS_REQUIRE_REVIEW"
        else:
            impact_category = "NO_EXISTING_ENI_ATTACHMENTS_OBSERVED"
    else:
        impact_category = "NOT_ASSESSED_FOR_DISRUPTION"
    return {
        "status": "CONTEXT_ERROR" if errors else "LIFECYCLE_CHANGE",
        "lifecycle_action": operation,
        "terraform_actions": actions,
        "security_group_id": old_id or new_id,
        "security_group_address": sg_address,
        "old_security_group_id": old_id,
        "new_security_group_id": new_id,
        "existing_dependencies": aws_context,
        "planned_dependencies": planned,
        "attachment_transitions": transitions,
        "impact_category": impact_category,
        "context_complete": False,
        "message": (
            "; ".join(errors) if errors else
            "Existing ENI attachments and changed root-module EC2/ENI attachment "
            "transitions investigated. SG deletion may be rejected if attachments "
            "remain; replacement does not establish service disruption or "
            "reachability. Other services and unchanged planned resources are not fully assessed."
        ),
    }

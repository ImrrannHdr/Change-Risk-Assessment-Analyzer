"""Read-only, conservative assessment for aws_security_group lifecycle changes."""
from __future__ import annotations

from typing import Any, Callable

from src.context.planned_sg_dependencies import find_planned_dependencies


def _old_sg_id(change: dict[str, Any]) -> str | None:
    before = (change.get("change") or {}).get("before") or {}
    value = before.get("id")
    return value if isinstance(value, str) and value.startswith("sg-") else None


def _new_sg_id(change: dict[str, Any]) -> str | None:
    after = (change.get("change") or {}).get("after") or {}
    unknown = (change.get("change") or {}).get("after_unknown") or {}
    if unknown.get("id"):
        return None
    value = after.get("id")
    return value if isinstance(value, str) and value.startswith("sg-") else None


def _aws_associations(sg_id: str, region: str, collector: Callable | None) -> dict:
    """Inspect ENIs for the existing SG. Caller must supply an authenticated collector or boto3 works."""
    if collector is not None:
        # Same collector shape as existing blast_radius.py.
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


def analyze_sg_lifecycle(
    plan: dict[str, Any],
    sg_address: str,
    region: str = "ap-southeast-2",
    resource_collector: Callable | None = None,
) -> dict[str, Any]:
    """Assess one whole-SG plan change; never mutate AWS or change scoring."""
    resource = next(
        (r for r in plan.get("resource_changes", [])
         if r.get("address") == sg_address and r.get("type") == "aws_security_group"),
        None,
    )
    if resource is None:
        return {"status": "NOT_ASSESSED", "context_complete": False,
                "message": "Whole-SG resource change not found in plan",
                "existing_dependencies": None, "planned_dependencies": None}

    actions = (resource.get("change") or {}).get("actions") or []
    old_id, new_id = _old_sg_id(resource), _new_sg_id(resource)
    replacing = "delete" in actions and "create" in actions
    deleting = actions == ["delete"]
    creating = actions == ["create"]
    updating = actions == ["update"]
    operation = "REPLACE" if replacing else "DELETE" if deleting else "CREATE" if creating else "UPDATE" if updating else "OTHER"

    # For replace/delete/update, inspect the OLD SG. A proposed new ID is not a deployed SG.
    existing_id = old_id if not creating else None
    aws_context = None
    errors = []
    if existing_id:
        try:
            aws_context = _aws_associations(existing_id, region, resource_collector)
        except Exception as exc:
            errors.append(f"AWS lookup failed: {type(exc).__name__}: {exc}")

    try:
        planned = find_planned_dependencies(
            plan, security_group_id=new_id or old_id,
            security_group_address=sg_address,
        )
    except Exception as exc:
        errors.append(f"Planned dependency lookup failed: {type(exc).__name__}: {exc}")
        planned = None

    return {
        "status": "CONTEXT_ERROR" if errors else "LIFECYCLE_CHANGE",
        "lifecycle_action": operation,
        "terraform_actions": actions,
        "security_group_id": existing_id or new_id,
        "security_group_address": sg_address,
        "old_security_group_id": old_id,
        "new_security_group_id": new_id,
        "existing_dependencies": aws_context,
        "planned_dependencies": planned,
        "context_complete": False,
        "message": (
            "; ".join(errors) if errors else
            f"Whole-SG {operation.lower()} detected. Existing ENI associations and supported "
            "planned EC2/ENI changes investigated where identifiable; dependency, "
            "reachability and actual disruption are not yet fully assessed."
        ),
    }

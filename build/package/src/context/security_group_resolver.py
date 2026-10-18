
from typing import Any

from src.context.terraform_references import (
    get_security_group_reference,
)


def resolve_security_group_id(
    plan: dict[str, Any],
    rule_address: str,
) -> dict[str, Any]:
    """
    Resolve a standalone security group rule to an
    existing AWS security group ID when possible.

    Does not call AWS.
    """
    sg_id = get_sg_id_from_rule_change(
        plan,
        rule_address,
    )

    if sg_id:
        return {
            "status": "resolved",
            "security_group_id": sg_id,
            "source": "terraform_resource_changes",
        }



    
    reference = get_security_group_reference(
        plan,
        rule_address,
    )

    if reference is None:
        return {"status": "unresolved"}

    # Case 1: The rule contains a literal AWS SG ID.
    if reference.get("resolution") == "aws_id":
        return {
            "status": "resolved",
            "security_group_id": reference["security_group_id"],
            "source": "literal",
        }

    # Case 2: The rule refers to a Terraform SG resource.
    address = reference.get("security_group_address")

    if not address:
        return {
            "status": "unresolved",
            "reference": reference,
        }

    # Find that security group in resource_changes.
    for resource in plan.get("resource_changes", []):
        if resource.get("address") != address:
            continue

        change = resource.get("change", {})
        before = change.get("before") or {}
        after = change.get("after") or {}
        actions = change.get("actions", [])

        # A newly created SG has no existing AWS ID.
        if actions == ["create"]:
            return {
                "status": "not_yet_created",
                "security_group_address": address,
            }

        # Prefer the proposed ID, falling back to prior ID.
        security_group_id = (
            after.get("id") or before.get("id")
        )

        if (
            isinstance(security_group_id, str)
            and security_group_id.startswith("sg-")
        ):
            return {
                "status": "resolved",
                "security_group_address": address,
                "security_group_id": security_group_id,
                "source": "terraform_plan",
            }

        return {
            "status": "unresolved",
            "security_group_address": address,
        }

    return {
        "status": "unresolved",
        "security_group_address": address,
    }



def get_sg_id_from_rule_change(plan, rule_address):
    """
    Resolve an existing SG ID directly from the
    standalone rule's Terraform planned values.

    This function does not call AWS.
    """

    for resource in plan.get("resource_changes", []):

        if resource.get("address") != rule_address:
            continue

        change = resource.get("change", {})
        after = change.get("after") or {}
        before = change.get("before") or {}
        unknown = change.get("after_unknown") or {}

        if unknown.get("security_group_id"):
            print(
                "[SG-RESOLVER] SG ID unknown until apply",
                flush=True,
            )
            return None

        sg_id = (
            after.get("security_group_id")
            or before.get("security_group_id")
        )

        if isinstance(sg_id, str) and sg_id.startswith("sg-"):

            print(
                f"[SG-RESOLVER] SG ID resolved from "
                f"Terraform resource_changes: {sg_id}",
                flush=True,
            )

            return sg_id

    return None
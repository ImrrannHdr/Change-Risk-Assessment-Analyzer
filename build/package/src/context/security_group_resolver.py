
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

    print(
        "\n========== SECURITY GROUP ID RESOLVER ==========",
        flush=True,
    )

    print(
        f"[SG-ID-RESOLVER] Starting SG ID resolution for rule: {rule_address}",
        flush=True,
    )

    # Step 1: Find the SG reference associated with the rule.
    print(
        "[SG-ID-RESOLVER] Calling get_security_group_reference()",
        flush=True,
    )

    reference = get_security_group_reference(
        plan,
        rule_address,
    )

    print(
        f"[SG-ID-RESOLVER] Reference resolution result: {reference}",
        flush=True,
    )

    # Step 2: Handle a rule that was not found.
    if reference is None:
        print(
            f"[SG-ID-RESOLVER] WARNING: No SG reference found for rule: {rule_address}",
            flush=True,
        )

        return {"status": "unresolved"}

    # Step 3: Handle a literal AWS security group ID.
    if reference.get("resolution") == "aws_id":

        security_group_id = reference["security_group_id"]

        print(
            f"[SG-ID-RESOLVER] SUCCESS: Literal AWS SG ID found: {security_group_id}",
            flush=True,
        )

        return {
            "status": "resolved",
            "security_group_id": security_group_id,
            "source": "literal",
        }

    # Step 4: Retrieve the referenced Terraform SG resource address.
    address = reference.get("security_group_address")

    print(
        f"[SG-ID-RESOLVER] Terraform SG resource address: {address}",
        flush=True,
    )

    # Step 5: Handle an unresolved Terraform reference.
    if not address:

        print(
            "[SG-ID-RESOLVER] WARNING: No valid Terraform SG resource address available",
            flush=True,
        )

        return {
            "status": "unresolved",
            "reference": reference,
        }

    # Step 6: Search Terraform resource changes for the SG.
    resource_changes = plan.get("resource_changes", [])

    print(
        f"[SG-ID-RESOLVER] Searching {len(resource_changes)} resource changes for SG: {address}",
        flush=True,
    )

    for resource in resource_changes:

        if resource.get("address") != address:
            continue

        print(
            f"[SG-ID-RESOLVER] Matching SG resource found: {address}",
            flush=True,
        )

        # Step 7: Extract before/after state and actions.
        change = resource.get("change", {})
        before = change.get("before") or {}
        after = change.get("after") or {}
        actions = change.get("actions", [])

        print(
            f"[SG-ID-RESOLVER] Planned actions: {actions}",
            flush=True,
        )

        print(
            f"[SG-ID-RESOLVER] Existing SG ID (before): {before.get('id')}",
            flush=True,
        )

        print(
            f"[SG-ID-RESOLVER] Proposed SG ID (after): {after.get('id')}",
            flush=True,
        )

        # Step 8: Detect newly created security groups.
        if actions == ["create"]:

            print(
                f"[SG-ID-RESOLVER] INFO: SG {address} is newly created and has no existing AWS ID",
                flush=True,
            )

            return {
                "status": "not_yet_created",
                "security_group_address": address,
            }

        # Step 9: Resolve an existing SG ID from the plan.
        # Prefer the proposed ID, falling back to the prior ID.
        security_group_id = (
            after.get("id") or before.get("id")
        )

        print(
            f"[SG-ID-RESOLVER] Candidate SG ID: {security_group_id}",
            flush=True,
        )

        # Step 10: Validate the AWS SG ID format.
        if (
            isinstance(security_group_id, str)
            and security_group_id.startswith("sg-")
        ):

            print(
                f"[SG-ID-RESOLVER] SUCCESS: Resolved AWS SG ID: {security_group_id}",
                flush=True,
            )

            print(
                "[SG-ID-RESOLVER] Resolution source: terraform_plan",
                flush=True,
            )

            return {
                "status": "resolved",
                "security_group_address": address,
                "security_group_id": security_group_id,
                "source": "terraform_plan",
            }

        # Step 11: Resource exists in the plan, but no usable SG ID.
        print(
            f"[SG-ID-RESOLVER] WARNING: No valid SG ID found for resource: {address}",
            flush=True,
        )

        return {
            "status": "unresolved",
            "security_group_address": address,
        }

    # Step 12: Referenced SG was not found in resource_changes.
    print(
        f"[SG-ID-RESOLVER] WARNING: SG {address} was not found in Terraform resource_changes",
        flush=True,
    )

    return {
        "status": "unresolved",
        "security_group_address": address,
    }

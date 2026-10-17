
from typing import Any


def get_security_group_reference(
    plan: dict[str, Any],
    rule_address: str,
) -> dict[str, Any] | None:
    """
    Find the security group referenced by a standalone
    security group rule in the Terraform root module.

    Returns a Terraform address when the rule references
    another resource directly, or a known literal SG ID.
    """

    print("\n========== SECURITY GROUP REFERENCE RESOLVER ==========", flush=True)
    print(f"[SG-RESOLVER] Starting resolution for rule: {rule_address}", flush=True)

    # Step 1: Retrieve Terraform configuration
    configuration = plan.get("configuration", {})
    root_module = configuration.get("root_module", {})
    resources = root_module.get("resources", [])

    print(
        f"[SG-RESOLVER] Found {len(resources)} resources in Terraform root module",
        flush=True,
    )

    # Step 2: Build a collection of managed security group addresses
    security_groups = {
        item["address"]
        for item in resources
        if item.get("type") == "aws_security_group"
        and item.get("mode", "managed") == "managed"
        and isinstance(item.get("address"), str)
    }

    print(
        f"[SG-RESOLVER] Found {len(security_groups)} managed security groups",
        flush=True,
    )

    print(
        f"[SG-RESOLVER] Security group addresses: {sorted(security_groups)}",
        flush=True,
    )

    # Step 3: Search for the requested security group rule
    for resource in resources:

        if resource.get("address") != rule_address:
            continue

        print(
            f"[SG-RESOLVER] Matching rule found: {rule_address}",
            flush=True,
        )

        # Step 4: Extract the security_group_id expression
        expression = (
            resource.get("expressions", {})
            .get("security_group_id", {})
        )

        print(
            f"[SG-RESOLVER] Security group expression: {expression}",
            flush=True,
        )

        # Step 5: Extract Terraform references
        references = expression.get("references", [])

        print(
            f"[SG-RESOLVER] Terraform references: {references}",
            flush=True,
        )

        # Step 6: Match against managed security groups
        for reference in references:

            print(
                f"[SG-RESOLVER] Checking reference: {reference}",
                flush=True,
            )

            if reference in security_groups:

                print(
                    f"[SG-RESOLVER] SUCCESS: Resolved Terraform SG reference: {reference}",
                    flush=True,
                )

                return {
                    "security_group_address": reference,
                    "resolution": "terraform_reference",
                }

        # Step 7: Check for a literal AWS security group ID
        constant = expression.get("constant_value")

        print(
            f"[SG-RESOLVER] Checking literal SG ID: {constant}",
            flush=True,
        )

        if isinstance(constant, str) and constant.startswith("sg-"):

            print(
                f"[SG-RESOLVER] SUCCESS: Found literal AWS SG ID: {constant}",
                flush=True,
            )

            return {
                "security_group_id": constant,
                "resolution": "aws_id",
            }

        # Step 8: Rule exists, but its SG could not be resolved
        print(
            f"[SG-RESOLVER] WARNING: Unable to resolve SG for rule: {rule_address}",
            flush=True,
        )

        print(
            f"[SG-RESOLVER] Unresolved references: {references}",
            flush=True,
        )

        return {
            "resolution": "unresolved",
            "references": references,
        }

    # Step 9: Requested rule was not found in root module
    print(
        f"[SG-RESOLVER] WARNING: Rule not found in Terraform root module: {rule_address}",
        flush=True,
    )

    return None

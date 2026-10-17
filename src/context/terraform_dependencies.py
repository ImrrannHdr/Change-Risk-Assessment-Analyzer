
from typing import Any


def find_planned_sg_dependencies(
    plan: dict[str, Any],
    security_group_address: str,
) -> dict[str, Any]:
    """
    Find root-module EC2 resources that directly
    reference a Terraform-managed security group.

    No AWS API calls are performed.
    """

    print(
        "\n========== TERRAFORM SG DEPENDENCY ANALYZER ==========",
        flush=True,
    )

    print(
        f"[SG-DEPENDENCIES] Starting dependency analysis for SG: {security_group_address}",
        flush=True,
    )

    # Step 1: Retrieve resources from Terraform root module.
    resources = (
        plan.get("configuration", {})
        .get("root_module", {})
        .get("resources", [])
    )

    print(
        f"[SG-DEPENDENCIES] Found {len(resources)} resources in Terraform root module",
        flush=True,
    )

    # Step 2: Initialize list for affected EC2 resources.
    affected_resources = []

    # Step 3: Define the expected Terraform SG references.
    expected_references = {
        security_group_address,
        f"{security_group_address}.id",
    }

    print(
        f"[SG-DEPENDENCIES] Looking for SG references: {sorted(expected_references)}",
        flush=True,
    )

    # Step 4: Iterate through Terraform resources.
    for resource in resources:

        resource_address = resource.get("address")
        resource_type = resource.get("type")
        resource_mode = resource.get("mode", "managed")

        print(
            f"[SG-DEPENDENCIES] Inspecting resource: {resource_address} "
            f"| Type: {resource_type} | Mode: {resource_mode}",
            flush=True,
        )

        # Step 5: Skip data sources and non-managed resources.
        if resource_mode != "managed":

            print(
                f"[SG-DEPENDENCIES] SKIPPED: Resource {resource_address} is not managed",
                flush=True,
            )

            continue

        # Step 6: Only inspect EC2 instances.
        if resource_type != "aws_instance":

            print(
                f"[SG-DEPENDENCIES] SKIPPED: {resource_address} is not an EC2 instance",
                flush=True,
            )

            continue

        print(
            f"[SG-DEPENDENCIES] EC2 instance found: {resource_address}",
            flush=True,
        )

        # Step 7: Retrieve the EC2 instance configuration expressions.
        expressions = resource.get("expressions", {})

        sg_expression = expressions.get(
            "vpc_security_group_ids", {}
        )

        print(
            f"[SG-DEPENDENCIES] SG attachment expression: {sg_expression}",
            flush=True,
        )

        # Step 8: Extract referenced Terraform resources.
        references = set(
            sg_expression.get("references", [])
        )

        print(
            f"[SG-DEPENDENCIES] EC2 SG references: {sorted(references)}",
            flush=True,
        )

        # Step 9: Compare EC2 references against the target SG.
        matched_references = references.intersection(
            expected_references
        )

        print(
            f"[SG-DEPENDENCIES] Matching SG references: {sorted(matched_references)}",
            flush=True,
        )

        # Step 10: Record EC2 instances referencing the target SG.
        if matched_references:

            print(
                f"[SG-DEPENDENCIES] MATCH FOUND: EC2 {resource_address} "
                f"references security group {security_group_address}",
                flush=True,
            )

            affected_resources.append(
                {
                    "address": resource_address,
                    "type": resource_type,
                    "relationship": "security_group_attachment",
                    "source": "terraform_configuration",
                }
            )

        else:

            print(
                f"[SG-DEPENDENCIES] NO MATCH: EC2 {resource_address} "
                "does not directly reference the target SG",
                flush=True,
            )

    # Step 11: Count all matching EC2 resources.
    resource_count = len(affected_resources)

    print(
        f"[SG-DEPENDENCIES] Dependency analysis completed",
        flush=True,
    )

    print(
        f"[SG-DEPENDENCIES] Total matching EC2 resources: {resource_count}",
        flush=True,
    )

    # Step 12: Display affected resources for debugging.
    for affected in affected_resources:

        print(
            f"[SG-DEPENDENCIES] Affected EC2: {affected['address']}",
            flush=True,
        )

    if not affected_resources:

        print(
            "[SG-DEPENDENCIES] No direct EC2 security group references "
            "found in Terraform root module",
            flush=True,
        )

    # Step 13: Return structured dependency information.
    return {
        "security_group_address": security_group_address,
        "affected_resources": affected_resources,
        "resource_count": resource_count,
        "scope": "root_module_direct_ec2_references",
    }

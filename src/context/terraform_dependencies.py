
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

    resources = (
        plan.get("configuration", {})
        .get("root_module", {})
        .get("resources", [])
    )

    affected_resources = []

    for resource in resources:
        if resource.get("mode", "managed") != "managed":
            continue

        if resource.get("type") != "aws_instance":
            continue

        expressions = resource.get("expressions", {})

        sg_expression = expressions.get(
            "vpc_security_group_ids", {}
        )

        references = set(
            sg_expression.get("references", [])
        )

        expected_references = {
            security_group_address,
            f"{security_group_address}.id",
        }

        if references.intersection(expected_references):
            affected_resources.append(
                {
                    "address": resource.get("address"),
                    "type": resource.get("type"),
                    "relationship": "security_group_attachment",
                    "source": "terraform_configuration",
                }
            )

    return {
        "security_group_address": security_group_address,
        "affected_resources": affected_resources,
        "resource_count": len(affected_resources),
        "scope": "root_module_direct_ec2_references",
    }

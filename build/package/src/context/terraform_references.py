
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

    configuration = plan.get("configuration", {})
    root_module = configuration.get("root_module", {})
    resources = root_module.get("resources", [])

    for resource in resources:
        if resource.get("address") != rule_address:
            continue

        expression = (
            resource.get("expressions", {})
            .get("security_group_id", {})
        )

        references = expression.get("references", [])

        # Match against actual managed security group
        # resources in the configuration.
        security_groups = {
            item["address"]
            for item in resources
            if item.get("type") == "aws_security_group"
            and item.get("mode", "managed") == "managed"
            and isinstance(item.get("address"), str)
        }

        for reference in references:
            if reference in security_groups:
                return {
                    "security_group_address": reference,
                    "resolution": "terraform_reference",
                }

        # Handle a literal security group ID.
        constant = expression.get("constant_value")

        if isinstance(constant, str) and constant.startswith("sg-"):
            return {
                "security_group_id": constant,
                "resolution": "aws_id",
            }

        return {
            "resolution": "unresolved",
            "references": references,
        }

    return None

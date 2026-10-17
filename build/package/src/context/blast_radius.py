from src.context.terraform_dependencies import (
    find_planned_sg_dependencies,
)


from typing import Any, Callable

from src.context.security_group_resolver import (
    resolve_security_group_id,
)
from src.context.ec2_context import (
    get_security_group_resources,
)


def analyze_security_group_impact(
    plan: dict[str, Any],
    rule_address: str,
    region: str = "ap-southeast-2",
    resource_collector: Callable | None = None,
) -> dict[str, Any]:
    """
    Discover potentially affected resources using:

    1. Terraform configuration references
    2. Existing AWS network interface associations

    This function does not calculate risk scores.
    """

    resolution = resolve_security_group_id(
        plan,
        rule_address,
    )

    status = resolution.get("status")
    sg_address = resolution.get("security_group_address")
    sg_id = resolution.get("security_group_id")


# Discover planned Terraform EC2 dependencies.
    planned_dependencies = None

    if sg_address:
        planned_dependencies = find_planned_sg_dependencies(
        plan,
        sg_address,
    )


    # Analyze direct Terraform EC2 dependencies.
    planned_dependencies = None

    if sg_address:
        planned_dependencies = find_planned_sg_dependencies(
            plan,
            sg_address,
        )

    # Case 1: New security group.
    if status == "not_yet_created":
        return {
            "status": "PLANNED_RESOURCE",
            "security_group_address": sg_address,
            "security_group_id": None,
            "planned_dependencies": planned_dependencies,
            "existing_dependencies": None,
            "context_complete": False,
            "message": (
                "New security group detected. "
                "Planned Terraform dependencies discovered "
                "within the supported analysis scope."
            ),
        }

    # Case 2: Unresolved security group.
    if status != "resolved" or not sg_id:
        return {
            "status": "UNRESOLVED",
            "security_group_address": sg_address,
            "planned_dependencies": planned_dependencies,
            "existing_dependencies": None,
            "context_complete": False,
            "message": (
                "Unable to resolve an existing AWS "
                "security group ID."
            ),
        }

    # Case 3: SG deletion or replacement.
    # Do not treat its previous AWS ID as the future ID.
    if sg_address:
        for resource in plan.get("resource_changes", []):
            if resource.get("address") != sg_address:
                continue

            actions = resource.get(
                "change", {}
            ).get("actions", [])

            if "delete" in actions:
                return {
                    "status": "LIFECYCLE_CHANGE",
                    "security_group_id": sg_id,
                    "security_group_address": sg_address,
                    "actions": actions,
                    "planned_dependencies": planned_dependencies,
                    "existing_dependencies": None,
                    "context_complete": False,
                    "message": (
                        "Security group deletion or replacement "
                        "requires separate lifecycle analysis."
                    ),
                }

    # Case 4: Existing security group.
    if resource_collector is None:
        resource_collector = get_security_group_resources

    # AWS API failures are intentionally propagated.
    # They must not be interpreted as zero affected resources.
    aws_context = resource_collector(
        security_group_id=sg_id,
        region=region,
    )

    existing_dependencies = {
        "ec2_instances": aws_context["instance_ids"],
        "instance_count": aws_context["instance_count"],
        "network_interfaces": aws_context["network_interfaces"],
        "network_interface_count": aws_context[
            "network_interface_count"
        ],
        "public_ip_detected": any(
            eni.get("public_ip")
            for eni in aws_context["network_interfaces"]
        ),
    }

    return {
        "status": "RESOLVED",
        "security_group_id": sg_id,
        "security_group_address": sg_address,
        "region": region,
        "planned_dependencies": planned_dependencies,
        "existing_dependencies": existing_dependencies,
        "context_complete": False,
        "message": (
            "Existing AWS associations and supported Terraform "
            "dependencies have been investigated. "
            "Full reachability and dependency analysis remains pending."
        ),
    }

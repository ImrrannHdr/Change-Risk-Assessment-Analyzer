
from typing import Any, Callable

from src.context.terraform_dependencies import (
    find_planned_sg_dependencies,
)
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

    print(
        "\n========== SECURITY GROUP BLAST RADIUS ANALYSIS ==========",
        flush=True,
    )

    print(
        f"[BLAST-RADIUS] Starting impact analysis for rule: {rule_address}",
        flush=True,
    )

    print(
        f"[BLAST-RADIUS] AWS Region: {region}",
        flush=True,
    )

    # ---------------------------------------------------------
    # Step 1: Resolve the security group associated with rule.
    # ---------------------------------------------------------

    print(
        "[BLAST-RADIUS] STEP 1: Resolving security group ID...",
        flush=True,
    )

    resolution = resolve_security_group_id(
        plan,
        rule_address,
    )

    print(
        f"[BLAST-RADIUS] SG resolution result: {resolution}",
        flush=True,
    )

    # Extract the resolution status, Terraform SG address,
    # and actual AWS security group ID (if available).
    status = resolution.get("status")
    sg_address = resolution.get("security_group_address")
    sg_id = resolution.get("security_group_id")

    print(
        f"[BLAST-RADIUS] Resolution status: {status}",
        flush=True,
    )

    print(
        f"[BLAST-RADIUS] Terraform SG address: {sg_address}",
        flush=True,
    )

    print(
        f"[BLAST-RADIUS] AWS Security Group ID: {sg_id}",
        flush=True,
    )

    # ---------------------------------------------------------
    # Step 2: Discover Terraform EC2 dependencies.
    # ---------------------------------------------------------

    print(
        "[BLAST-RADIUS] STEP 2: Checking Terraform planned dependencies...",
        flush=True,
    )

    planned_dependencies = None

    if sg_address:

        print(
            f"[BLAST-RADIUS] Searching Terraform resources referencing: {sg_address}",
            flush=True,
        )

        planned_dependencies = find_planned_sg_dependencies(
            plan,
            sg_address,
        )

        print(
            "[BLAST-RADIUS] Terraform dependency analysis completed",
            flush=True,
        )

        print(
            "[BLAST-RADIUS] Planned EC2 dependency count: "
            f"{planned_dependencies.get('resource_count', 0)}",
            flush=True,
        )

        print(
            "[BLAST-RADIUS] Planned affected resources: "
            f"{planned_dependencies.get('affected_resources', [])}",
            flush=True,
        )

    else:

        print(
            "[BLAST-RADIUS] WARNING: Terraform SG address unavailable. "
            "Skipping planned dependency discovery.",
            flush=True,
        )

    # ---------------------------------------------------------
    # Step 3: Handle newly created security groups.
    # ---------------------------------------------------------

    if status == "not_yet_created":

        print(
            "[BLAST-RADIUS] CASE 1: Newly created security group detected",
            flush=True,
        )

        print(
            "[BLAST-RADIUS] Existing AWS ID is not available. "
            "Skipping AWS resource discovery.",
            flush=True,
        )

        print(
            "[BLAST-RADIUS] Returning PLANNED_RESOURCE result",
            flush=True,
        )

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

    # ---------------------------------------------------------
    # Step 4: Handle unresolved security groups.
    # ---------------------------------------------------------

    if status != "resolved" or not sg_id:

        print(
            "[BLAST-RADIUS] CASE 2: Unable to resolve existing AWS SG ID",
            flush=True,
        )

        print(
            f"[BLAST-RADIUS] Resolution status: {status}",
            flush=True,
        )

        print(
            "[BLAST-RADIUS] WARNING: AWS dependency discovery "
            "cannot proceed without a valid SG ID.",
            flush=True,
        )

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

    # ---------------------------------------------------------
    # Step 5: Check SG deletion or replacement lifecycle.
    # ---------------------------------------------------------

    print(
        "[BLAST-RADIUS] STEP 3: Checking security group lifecycle changes...",
        flush=True,
    )

    if sg_address:

        for resource in plan.get("resource_changes", []):

            if resource.get("address") != sg_address:
                continue

            actions = resource.get(
                "change", {}
            ).get("actions", [])

            print(
                f"[BLAST-RADIUS] SG planned actions: {actions}",
                flush=True,
            )

            # An existing SG may be deleted or replaced.
            # Its old AWS ID must not be treated as the new SG ID.
            if "delete" in actions:

                print(
                    "[BLAST-RADIUS] CASE 3: Security group deletion "
                    "or replacement detected",
                    flush=True,
                )

                print(
                    "[BLAST-RADIUS] WARNING: Existing SG ID refers "
                    "to the current resource, not its replacement.",
                    flush=True,
                )

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

    print(
        "[BLAST-RADIUS] No SG deletion or replacement detected",
        flush=True,
    )

    # ---------------------------------------------------------
    # Step 6: Discover existing AWS resource associations.
    # ---------------------------------------------------------

    print(
        "[BLAST-RADIUS] STEP 4: Starting AWS resource discovery...",
        flush=True,
    )

    # Use the default boto3-based collector unless a custom
    # collector was injected (for example, during unit testing).
    if resource_collector is None:

        print(
            "[BLAST-RADIUS] Using default AWS resource collector",
            flush=True,
        )

        resource_collector = get_security_group_resources

    else:

        print(
            "[BLAST-RADIUS] Using custom resource collector",
            flush=True,
        )

    print(
        f"[BLAST-RADIUS] Querying AWS for resources attached to SG: {sg_id}",
        flush=True,
    )

    # AWS API failures are intentionally propagated.
    # A discovery failure must not be interpreted as zero resources.
    try:

        aws_context = resource_collector(
            security_group_id=sg_id,
            region=region,
        )

    except Exception as error:

        print(
            "[BLAST-RADIUS] ERROR: AWS resource discovery failed",
            flush=True,
        )

        print(
            f"[BLAST-RADIUS] Exception type: {type(error).__name__}",
            flush=True,
        )

        print(
            f"[BLAST-RADIUS] Exception details: {error}",
            flush=True,
        )

        # Re-raise so the calling service can record
        # CONTEXT_ERROR rather than reporting no dependencies.
        raise

    print(
        "[BLAST-RADIUS] AWS resource discovery completed successfully",
        flush=True,
    )

    # ---------------------------------------------------------
    # Step 7: Extract existing EC2 and ENI dependencies.
    # ---------------------------------------------------------

    instance_ids = aws_context["instance_ids"]
    instance_count = aws_context["instance_count"]

    network_interfaces = aws_context["network_interfaces"]
    network_interface_count = aws_context[
        "network_interface_count"
    ]

    print(
        f"[BLAST-RADIUS] Existing EC2 instance count: {instance_count}",
        flush=True,
    )

    print(
        f"[BLAST-RADIUS] Existing EC2 instance IDs: {instance_ids}",
        flush=True,
    )

    print(
        f"[BLAST-RADIUS] Existing network interface count: {network_interface_count}",
        flush=True,
    )

    # Print essential ENI information without dumping
    # the complete AWS API response.
    for eni in network_interfaces:

        print(
            "[BLAST-RADIUS] ENI discovered | "
            f"ENI ID: {eni.get('network_interface_id')} | "
            f"Instance ID: {eni.get('instance_id')} | "
            f"Public IP: {eni.get('public_ip')}",
            flush=True,
        )

    # ---------------------------------------------------------
    # Step 8: Detect ENIs associated with public IPs.
    # ---------------------------------------------------------

    public_ip_detected = any(
        eni.get("public_ip")
        for eni in network_interfaces
    )

    print(
        f"[BLAST-RADIUS] Public IP detected: {public_ip_detected}",
        flush=True,
    )

    # ---------------------------------------------------------
    # Step 9: Build existing AWS dependency information.
    # ---------------------------------------------------------

    existing_dependencies = {
        "ec2_instances": instance_ids,
        "instance_count": instance_count,
        "network_interfaces": network_interfaces,
        "network_interface_count": network_interface_count,
        "public_ip_detected": public_ip_detected,
    }

    print(
        "[BLAST-RADIUS] Existing AWS dependency summary created",
        flush=True,
    )

    # ---------------------------------------------------------
    # Step 10: Return consolidated blast-radius result.
    # ---------------------------------------------------------

    print(
        "[BLAST-RADIUS] CASE 4: Existing security group resolved",
        flush=True,
    )

    print(
        "[BLAST-RADIUS] Final status: RESOLVED",
        flush=True,
    )

    print(
        "[BLAST-RADIUS] Context complete: False "
        "(full reachability analysis not yet implemented)",
        flush=True,
    )

    print(
        "========== BLAST RADIUS ANALYSIS FINISHED ==========\n",
        flush=True,
    )

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

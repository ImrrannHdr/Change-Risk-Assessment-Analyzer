
import boto3
from typing import Any


def get_security_group_resources(
    security_group_id: str,
    region: str = "ap-southeast-2",
    ec2_client: Any = None,
) -> dict[str, Any]:
    """
    Discover existing AWS network interfaces associated
    with a security group.

    Return attached EC2 instance IDs when available.
    """

    if not security_group_id.startswith("sg-"):
        raise ValueError("Expected an AWS security group ID")

    if ec2_client is None:
        ec2_client = boto3.client("ec2", region_name=region)

    paginator = ec2_client.get_paginator(
        "describe_network_interfaces"
    )

    network_interfaces = []
    instance_ids = set()

    pages = paginator.paginate(
        Filters=[
            {
                "Name": "group-id",
                "Values": [security_group_id],
            }
        ]
    )

    for page in pages:
        for eni in page.get("NetworkInterfaces", []):
            attachment = eni.get("Attachment") or {}
            instance_id = attachment.get("InstanceId")

            if instance_id:
                instance_ids.add(instance_id)

            network_interfaces.append(
                {
                    "network_interface_id": eni.get(
                        "NetworkInterfaceId"
                    ),
                    "interface_type": eni.get(
                        "InterfaceType"
                    ),
                    "description": eni.get("Description"),
                    "vpc_id": eni.get("VpcId"),
                    "subnet_id": eni.get("SubnetId"),
                    "private_ip": eni.get(
                        "PrivateIpAddress"
                    ),
                    "public_ip": (
                        eni.get("Association") or {}
                    ).get("PublicIp"),
                    "instance_id": instance_id,
                }
            )

    return {
        "security_group_id": security_group_id,
        "region": region,
        "network_interfaces": network_interfaces,
        "instance_ids": sorted(instance_ids),
        "network_interface_count": len(network_interfaces),
        "instance_count": len(instance_ids),
    }

"""Stage 3B: read-only, current-state VPC subnet and ENI route-table dependencies.

This does not mutate AWS and does not establish application traffic dependencies.
"""
from __future__ import annotations

from typing import Any
import boto3


def _pages(ec2: Any, operation: str, result_key: str, **kwargs: Any) -> list[dict]:
    return [item for page in ec2.get_paginator(operation).paginate(**kwargs)
            for item in page.get(result_key, [])]


def discover_route_table_context(route_table_id: str, region: str = "ap-southeast-2", *, ec2: Any = None,
                                 max_subnets: int = 1000, max_enis: int = 5000) -> dict[str, Any]:
    """Discover subnet association and ENI exposure for an *existing* route table.

    Raises on AWS API errors or explicit inventory limits (fail closed).
    Returns separate explicit/implicit subnet mappings. Gateway associations are not
    subnet associations and are intentionally reported as unsupported scope.
    """
    if not isinstance(route_table_id, str) or not route_table_id.startswith("rtb-"):
        raise ValueError("An existing rtb-* route_table_id is required")
    ec2 = ec2 or boto3.client("ec2", region_name=region)
    selected = _pages(ec2, "describe_route_tables", "RouteTables", RouteTableIds=[route_table_id])
    if len(selected) != 1:
        raise ValueError(f"Expected one route table for {route_table_id}, found {len(selected)}")
    current = selected[0]
    vpc_id = current["VpcId"]
    tables = _pages(ec2, "describe_route_tables", "RouteTables",
                    Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    main = [t["RouteTableId"] for t in tables
            if any(a.get("Main") is True for a in t.get("Associations", []))]
    if len(main) != 1:
        raise ValueError("Cannot uniquely resolve the VPC main route table")
    main_id = main[0]
    explicit: dict[str, str] = {}
    gateway_associations: list[dict] = []
    for table in tables:
        for association in table.get("Associations", []):
            if association.get("SubnetId"):
                sid = association["SubnetId"]
                if sid in explicit:
                    raise ValueError(f"Duplicate explicit association for subnet {sid}")
                explicit[sid] = table["RouteTableId"]
            elif association.get("GatewayId"):
                gateway_associations.append({"route_table_id": table["RouteTableId"],
                                             "gateway_id": association["GatewayId"]})
    subnets = _pages(ec2, "describe_subnets", "Subnets", Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    if len(subnets) > max_subnets:
        raise ValueError("Subnet inventory exceeds safety limit; assessment incomplete")
    affected: list[dict] = []
    for subnet in subnets:
        sid = subnet["SubnetId"]
        is_explicit = sid in explicit
        effective = explicit.get(sid, main_id)
        if effective == route_table_id:
            affected.append({"subnet_id": sid, "cidr_block": subnet.get("CidrBlock"),
                             "availability_zone": subnet.get("AvailabilityZone"),
                             "association_type": "EXPLICIT" if is_explicit else "IMPLICIT"})
    affected.sort(key=lambda s: s["subnet_id"])
    enis: list[dict] = []
    for subnet in affected:
        sid = subnet["subnet_id"]
        raw = _pages(ec2, "describe_network_interfaces", "NetworkInterfaces",
                     Filters=[{"Name": "subnet-id", "Values": [sid]}])
        for eni in raw:
            enis.append({"eni_id": eni.get("NetworkInterfaceId"), "subnet_id": sid,
                         "interface_type": eni.get("InterfaceType"),
                         "description": eni.get("Description"),
                         "status": eni.get("Status"),
                         "instance_id": (eni.get("Attachment") or {}).get("InstanceId")})
        if len(enis) > max_enis:
            raise ValueError("ENI inventory exceeds safety limit; assessment incomplete")
    return {
        "status": "RESOLVED", "context_complete": False,
        "scope": "CURRENT_AWS_STATE_SUBNET_ENI_ONLY",
        "route_table_id": route_table_id, "vpc_id": vpc_id, "main_route_table_id": main_id,
        "is_main_route_table": route_table_id == main_id,
        "routes": current.get("Routes", []),
        "affected_subnets": affected, "affected_subnet_count": len(affected),
        "explicit_subnet_count": sum(s["association_type"] == "EXPLICIT" for s in affected),
        "implicit_subnet_count": sum(s["association_type"] == "IMPLICIT" for s in affected),
        "network_interfaces": enis, "network_interface_count": len(enis),
        "ec2_instance_ids": sorted({e["instance_id"] for e in enis if e["instance_id"]}),
        "gateway_associations": [a for a in gateway_associations if a["route_table_id"] == route_table_id],
        "limitations": ["Current AWS snapshot only; planned association changes not applied",
                        "ENIs are potential dependencies, not evidence of actual traffic",
                        "Gateway/edge associations require separate analysis"],
    }

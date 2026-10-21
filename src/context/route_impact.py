"""Stage 3C: conservative, read-only route change impact evidence.

For destination-CIDR changes, models the static route candidates. Never claims
end-to-end reachability or a proven outage. Does not update scoring/decisions.
"""
from __future__ import annotations

import ipaddress
from typing import Any

from src.context.route_context import discover_route_table_context

DEST_KEYS = ("destination_cidr_block", "destination_ipv6_cidr_block", "cidr_block", "ipv6_cidr_block", "DestinationCidrBlock", "DestinationIpv6CidrBlock")
TARGET_KEYS = ("transit_gateway_id", "nat_gateway_id", "gateway_id", "vpc_peering_connection_id",
               "network_interface_id", "instance_id", "egress_only_gateway_id", "local_gateway_id",
               "carrier_gateway_id", "vpc_endpoint_id", "core_network_arn")


def _dest(obj: dict) -> str | None:
    source = obj.get("destinations", obj)
    return next((str(source[k]) for k in DEST_KEYS if source.get(k)), None)


def _target(obj: dict) -> dict:
    source = obj.get("targets", obj)
    target = {k: source[k] for k in TARGET_KEYS if source.get(k)}
    if source.get("GatewayId") and not target:
        target["gateway_id"] = source["GatewayId"]
    camel_keys = {"TransitGatewayId": "transit_gateway_id", "NatGatewayId": "nat_gateway_id",
                  "GatewayId": "gateway_id", "VpcPeeringConnectionId": "vpc_peering_connection_id",
                  "NetworkInterfaceId": "network_interface_id", "InstanceId": "instance_id",
                  "EgressOnlyInternetGatewayId": "egress_only_gateway_id", "LocalGatewayId": "local_gateway_id",
                  "CarrierGatewayId": "carrier_gateway_id", "VpcEndpointId": "vpc_endpoint_id",
                  "CoreNetworkArn": "core_network_arn"}
    for camel, snake in camel_keys.items():
        if source.get(camel) and snake not in target:
            target[snake] = source[camel]
    return target


def _static_candidate(routes: list[dict], destination: str, *, exclude: str | None = None) -> dict:
    """Return best CIDR candidate, but mark ambiguous/unsupported selection honestly."""
    try:
        dst_net = ipaddress.ip_network(destination, strict=False)
    except (ValueError, TypeError):
        return {"status": "INCOMPLETE", "reason": "Unsupported/non-CIDR destination"}
    matches = []
    unknown = False
    for route in routes:
        cidr = _dest(route)
        if route.get("DestinationPrefixListId") or route.get("destination_prefix_list_id"):
            unknown = True
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            unknown = True
            continue
        if network.version != dst_net.version or not dst_net.subnet_of(network):
            continue
        if exclude and cidr == exclude:
            continue
        matches.append((network.prefixlen, route))
    if unknown:
        return {"status": "INCOMPLETE", "reason": "Prefix-list or unparseable route may affect selection"}
    if not matches:
        return {"status": "NO_CIDR_MATCH", "route": None}
    longest = max(x[0] for x in matches)
    best = [r for plen, r in matches if plen == longest]
    if len(best) != 1:
        return {"status": "INCOMPLETE", "reason": "Multiple matching routes with equal prefix length"}
    chosen = best[0]
    # A propagated route can be superseded; without full AWS route precedence modelling
    # we conservatively report selection as incomplete.
    if chosen.get("Origin") not in (None, "CreateRoute", "CreateRouteTable"):
        return {"status": "INCOMPLETE", "reason": "Propagated/other route origin requires precedence analysis"}
    return {"status": "CANDIDATE", "destination": _dest(chosen), "target": _target(chosen),
            "route_state": chosen.get("State")}


def assess_route_change(change: dict[str, Any], *, region: str = "ap-southeast-2",
                        ec2: Any = None) -> dict[str, Any]:
    """Assess a Stage 3A record against a single current-state AWS route table.

    Supports standalone aws_route CREATE/DELETE/UPDATE/REPLACE. Whole route-table
    and association operations are identified but deliberately not extrapolated.
    """
    resource_type = change.get("resource_type")
    action = change.get("lifecycle_action")
    before = change.get("before") or {}
    after = change.get("after") or {}
    if resource_type != "aws_route":
        return {"status": "NOT_ASSESSED", "resource": change.get("resource"),
                "context_complete": False,
                "reason": "Stage 3C association/whole-table before-after mapping is not implemented"}
    table_id = before.get("route_table_id") or after.get("route_table_id")
    if not isinstance(table_id, str) or not table_id.startswith("rtb-"):
        return {"status": "INCOMPLETE", "context_complete": False,
                "resource": change.get("resource"), "reason": "Existing route table ID unresolved"}
    current = discover_route_table_context(table_id, region=region, ec2=ec2)
    old_dest, new_dest = _dest(before), _dest(after)
    old_target, new_target = _target(before), _target(after)
    # Distinct destination replacements alter different traffic prefixes. Do not
    # misrepresent the old/new route selection as if they were one destination.
    if old_dest and new_dest and old_dest != new_dest:
        route_selection = {"status": "INCOMPLETE", "reason": "Destination changed; two-prefix evaluation required"}
    elif action not in {"CREATE", "DELETE", "UPDATE", "REPLACE"}:
        route_selection = {"status": "INCOMPLETE", "reason": "Unsupported lifecycle action"}
    elif change.get("unknown_paths"):
        route_selection = {"status": "INCOMPLETE", "reason": "Terraform has unknown planned attributes"}
    elif any(
        (side.get("destinations") or {}).get("destination_prefix_list_id")
        for side in (before, after)
    ):
        route_selection = {"status": "INCOMPLETE", "reason": "Prefix list expansion unsupported"}
    else:
        destination = old_dest or new_dest
        if not destination:
            route_selection = {"status": "INCOMPLETE", "reason": "CIDR destination unresolved"}
        else:
            # Baseline current AWS route table; do not assume this equals Terraform's
            # intended before state (drift is possible). Model removal/addition only.
            old_candidate = _static_candidate(current["routes"], destination)
            remaining_routes = [r for r in current["routes"] if _dest(r) != destination]
            if action == "DELETE":
                after_candidate = _static_candidate(remaining_routes, destination)
            elif action in {"CREATE", "UPDATE", "REPLACE"}:
                proposed = {"DestinationCidrBlock" if ":" not in destination else "DestinationIpv6CidrBlock": destination}
                proposed.update(new_target)
                after_candidate = _static_candidate(remaining_routes + [proposed], destination)
            else:
                after_candidate = {"status": "INCOMPLETE"}
            if action in {"DELETE", "UPDATE", "REPLACE"} and (
                old_candidate.get("status") != "CANDIDATE"
                or old_candidate.get("destination") != destination
                or (old_target and old_candidate.get("target") != old_target)
            ):
                route_selection = {"status": "INCOMPLETE", "reason":
                    "Current AWS winning route does not match planned before state; drift or precedence possible",
                    "current_candidate": old_candidate}
            else:
                route_selection = {"status": "CANDIDATE_ONLY", "current_candidate": old_candidate,
                                   "proposed_candidate": after_candidate,
                                   "note": "Route table snapshot may drift; selection is not a reachability proof"}
    return {
        "status": "PARTIAL", "resource": change.get("resource"), "action": action,
        "route_table_id": table_id, "destination_before": old_dest, "destination_after": new_dest,
        "target_before": old_target, "target_after": new_target,
        "dependency_discovery": current, "route_selection": route_selection,
        "potential_impact": ("No current subnet ENIs observed" if current["network_interface_count"] == 0
                             else "ENIs in associated subnets may use the changed destination"),
        "context_complete": False,
        "limitations": ["Not proof of packet flow or outage", "Plan-time association moves not modelled",
                        "NACL, SG, TGW return path and propagated/prefix-list precedence not fully modelled"],
    }

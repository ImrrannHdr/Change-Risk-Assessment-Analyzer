"""Advisory comparison of existing subnet route-table candidate paths.

Never claims reachability; excludes prefix-list and propagated precedence.
"""
from __future__ import annotations
import ipaddress
from typing import Any

TARGET_KEYS = ("GatewayId", "NatGatewayId", "TransitGatewayId", "VpcPeeringConnectionId",
               "NetworkInterfaceId", "InstanceId", "EgressOnlyInternetGatewayId",
               "LocalGatewayId", "CarrierGatewayId", "CoreNetworkArn", "VpcEndpointId")


def _candidate(routes: list[dict], destination: str) -> dict[str, Any]:
    """Select longest matching static CIDR candidate for representative destination IP."""
    dest = ipaddress.ip_network(destination, strict=False)
    probe = dest.network_address
    candidates = []
    for route in routes:
        cidr = route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock")
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return {"status": "INCOMPLETE", "reason": "Invalid route destination CIDR"}
        if net.version == probe.version and probe in net:
            candidates.append((net.prefixlen, route))
    if not candidates:
        return {"status": "NO_CIDR_MATCH"}
    most_specific = max(n for n, _ in candidates)
    best = [r for n, r in candidates if n == most_specific]
    if len(best) != 1:
        return {"status": "INCOMPLETE", "reason": "Equal-length candidates require precedence resolution"}
    route = best[0]
    return {"status": "CANDIDATE", "destination": route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock"),
            "target": {k: route[k] for k in TARGET_KEYS if route.get(k)}, "route_state": route.get("State")}


def compare_route_sets(before_routes: list[dict], after_routes: list[dict], *, max_destinations: int = 100) -> dict[str, Any]:
    """Compare known IPv4/IPv6 CIDR route entries, including fallback candidate.

    This is a snapshot-only analysis. CIDR network-address probes are not exhaustive
    for overlapping more-specific routes, so statuses are advisory, never COMPLETE.
    """
    all_routes = before_routes + after_routes
    if any(r.get("DestinationPrefixListId") for r in all_routes):
        return {"status": "INCOMPLETE", "reason": "Prefix-list expansion is unsupported", "changes": []}
    if any(r.get("Origin") == "EnableVgwRoutePropagation" for r in all_routes):
        return {"status": "INCOMPLETE", "reason": "Propagated route precedence is unsupported", "changes": []}
    destinations = sorted({r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock")
                           for r in all_routes if r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock")})
    if len(destinations) > max_destinations:
        return {"status": "INCOMPLETE", "reason": "Route destination comparison limit exceeded", "changes": []}
    changes = []
    for dest in destinations:
        try:
            prior = _candidate(before_routes, dest)
            planned = _candidate(after_routes, dest)
        except ValueError:
            return {"status": "INCOMPLETE", "reason": "Invalid CIDR encountered", "changes": []}
        if prior != planned:
            changes.append({"destination": dest, "before_candidate": prior, "after_candidate": planned})
    return {"status": "CANDIDATE_ONLY", "changed_destination_count": len(changes),
            "changes": changes, "context_complete": False,
            "note": "CIDR route candidate snapshots only; not exhaustive reachability or live traffic evidence"}

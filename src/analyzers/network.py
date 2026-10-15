import ipaddress
from pathlib import Path
from typing import Any

import yaml

from src.common.models import Change, Finding

POLICY_PATH = (
    Path(__file__).resolve().parents[2]
    / "config"
    / "risk_policy.yaml"
)

SUPPORTED_TYPES = {
    "aws_security_group",
    "aws_security_group_rule",
    "aws_vpc_security_group_ingress_rule",
}


def load_network_policy() -> dict:
    print(f"--> Loading risk policy configuration from: {POLICY_PATH}")
    with POLICY_PATH.open("r", encoding="utf-8") as file:
        document = yaml.safe_load(file)

    if not isinstance(document, dict):
        raise ValueError("Invalid risk_policy.yaml")

    policy = document.get("network")

    if not isinstance(policy, dict):
        raise ValueError("Missing network policy configuration")

    required = {
        "sensitive_ports",
        "public_exposure",
        "hard_block_sensitive_ports",
        "broad_ipv4_prefix_max",
        "broad_ipv6_prefix_max",
    }

    if not required.issubset(policy):
        raise ValueError("Incomplete network policy configuration")

    exposure = policy["public_exposure"]

    if (
        not isinstance(exposure, dict)
        or "high_risk_points" not in exposure
        or "critical_risk_points" not in exposure
    ):
        raise ValueError("Invalid public_exposure configuration")

    print("--> Policy configuration loaded and verified successfully.")
    return policy


def _ingress_rules(value: dict | None) -> list[dict]:
    if not isinstance(value, dict):
        return []

    rules = value.get("ingress", [])

    return rules if isinstance(rules, list) else []


def _cidrs(rule: dict) -> list[str]:
    values = []

    for field in ("cidr_blocks", "ipv6_cidr_blocks"):
        item = rule.get(field, [])

        if isinstance(item, str):
            values.append(item)
        elif isinstance(item, list):
            values.extend(v for v in item if isinstance(v, str))

    for field in ("cidr_ipv4", "cidr_ipv6"):
        item = rule.get(field)

        if isinstance(item, str):
            values.append(item)

    return values


def _is_broad_public(cidr: str, policy: dict) -> bool:
    try:
        network = ipaddress.ip_network(cidr, strict=False)

        if network.version == 4:
            limit = policy["broad_ipv4_prefix_max"]
        else:
            limit = policy["broad_ipv6_prefix_max"]

        is_broad = network.prefixlen <= int(limit)
        if is_broad:
            print(f"    [!] Detected broad public CIDR: {cidr} (Prefix length /{network.prefixlen} <= /{limit})")
        return is_broad

    except ValueError:
        return False


def _normalized_rules(
    change: Change,
    value: dict | None,
) -> set[tuple]:
    if not isinstance(value, dict):
        return set()

    if change.resource_type == "aws_security_group":
        rules = _ingress_rules(value)

    elif change.resource_type == "aws_security_group_rule":
        if value.get("type") != "ingress":
            return set()
        rules = [value]

    elif change.resource_type == "aws_vpc_security_group_ingress_rule":
        rules = [value]

    else:
        return set()

    normalized = set()

    for rule in rules:
        protocol = str(
            rule.get("ip_protocol", rule.get("protocol", ""))
        ).lower()

        from_port = rule.get("from_port")
        to_port = rule.get("to_port")

        for cidr in _cidrs(rule):
            try:
                canonical_cidr = str(
                    ipaddress.ip_network(cidr, strict=False)
                )
            except ValueError:
                continue

            normalized.add(
                (protocol, from_port, to_port, canonical_cidr)
            )

    return normalized


def _exposes_sensitive_port(
    protocol: str,
    from_port: Any,
    to_port: Any,
    sensitive_ports: set[int],
) -> bool:
    if protocol == "-1":
        print("    [CRITICAL] Rule specifies protocol '-1' (All protocols/ports open)!")
        return True

    if protocol not in {"tcp", "udp", "6", "17"}:
        return False

    if not isinstance(from_port, int) or not isinstance(to_port, int):
        return False

    for port in sensitive_ports:
        if from_port <= port <= to_port:
            print(f"    [CRITICAL] Rule exposes sensitive port: {port} inside range {from_port}-{to_port}")
            return True

    return False


def analyze(
    changes: list[Change],
    policy: dict | None = None,
) -> list[Finding]:
    if policy is None:
        policy = load_network_policy()

    findings: list[Finding] = []
    sensitive_ports = set(policy["sensitive_ports"])
    hard_block_enabled = policy["hard_block_sensitive_ports"]

    print(f"--> Commencing network scan on {len(changes)} total change items...")

    for index, change in enumerate(changes, start=1):
        print(f"\n[{index}/{len(changes)}] Processing resource: {change.address} ({change.resource_type})")

        if change.resource_type not in SUPPORTED_TYPES:
            print(f"    [-] Skipping: Resource type '{change.resource_type}' is not a tracked network resource.")
            continue

        before_rules = _normalized_rules(change, change.before)
        after_rules = _normalized_rules(change, change.after)

        new_rules = after_rules - before_rules
        print(f"    [i] Found {len(new_rules)} net-new rule variations to inspect.")

        if not new_rules:
            continue

        new_public = [
            rule
            for rule in new_rules
            if _is_broad_public(rule[3], policy)
        ]

        if not new_public:
            print("    [✓] No broad public exposures introduced by this change.")
            continue

        print(f"    [!] Identified {len(new_public)} broad public exposures.")
        new_public.sort(key=str)

        hard_block = hard_block_enabled and any(
            _exposes_sensitive_port(
                protocol,
                from_port,
                to_port,
                sensitive_ports,
            )
            for protocol, from_port, to_port, _ in new_public
        )

        points = (
            policy["public_exposure"]["critical_risk_points"]
            if hard_block
            else policy["public_exposure"]["high_risk_points"]
        )
        severity = "CRITICAL" if hard_block else "HIGH"
        
        print(f"    [!] Action required: Generated {severity} security finding! (Risk Penalty: {points} pts)")

        findings.append(
            Finding(
                category="INTERNET_EXPOSURE",
                severity=severity,
                risk_points=points,
                resource=change.address,
                message=(
                    "Security group introduces new "
                    "broad Internet exposure."
                ),
                evidence={
                    "new_public_rules": [
                        {
                            "protocol": protocol,
                            "from_port": from_port,
                            "to_port": to_port,
                            "cidr": cidr,
                        }
                        for protocol, from_port, to_port, cidr
                        in new_public
                    ]
                },
                hard_block=hard_block,
            )
        )
        
    print(f"\n--> Security scan finished. Found {len(findings)} network findings.")
    return findings

# Build by Imran Haider
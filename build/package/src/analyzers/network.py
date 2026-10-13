import ipaddress

from src.common.models import Change, Finding

SENSITIVE_PORTS = {22, 3389, 3306, 5432}


def _ingress_rules(value: dict | None) -> list[dict]:
    if not isinstance(value, dict):
        return []
    rules = value.get("ingress", [])
    return rules if isinstance(rules, list) else []


def _cidrs(rule: dict) -> list[str]:
    values = rule.get("cidr_blocks", [])
    if isinstance(values, str):
        return [values]
    return values if isinstance(values, list) else []


def _is_public(cidr: str) -> bool:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return network.prefixlen == 0
    except ValueError:
        return False


def analyze(changes: list[Change]) -> list[Finding]:
    findings: list[Finding] = []

    for change in changes:
        if change.resource_type != "aws_security_group":
            continue

        before_rules = _ingress_rules(change.before)
        after_rules = _ingress_rules(change.after)

        before_public = {
            (r.get("from_port"), r.get("to_port"), c)
            for r in before_rules
            for c in _cidrs(r)
            if _is_public(c)
        }
        after_public = {
            (r.get("from_port"), r.get("to_port"), c)
            for r in after_rules
            for c in _cidrs(r)
            if _is_public(c)
        }

        new_public = sorted(after_public - before_public)
        if new_public:
            hard_block = any(
                fp in SENSITIVE_PORTS or tp in SENSITIVE_PORTS
                for fp, tp, _ in new_public
            )
            findings.append(
                Finding(
                    category="INTERNET_EXPOSURE",
                    severity="CRITICAL" if hard_block else "HIGH",
                    risk_points=40 if hard_block else 35,
                    resource=change.address,
                    message="Security group introduces new Internet exposure.",
                    evidence={"new_public_rules": new_public},
                    hard_block=hard_block,
                )
            )

    return findings

# Build by Imran Haider

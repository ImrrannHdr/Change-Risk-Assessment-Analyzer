
from types import SimpleNamespace

from src.analyzers.network import analyze


TEST_POLICY = {
    "sensitive_ports": [22, 3389, 3306, 5432],
    "hard_block_sensitive_ports": True,
    "broad_ipv4_prefix_max": 1,
    "broad_ipv6_prefix_max": 1,
    "public_exposure": {
        "high_risk_points": 35,
        "critical_risk_points": 40,
    },
}


def make_change(resource_type, before, after):
    return SimpleNamespace(
        resource_type=resource_type,
        before=before,
        after=after,
        address="aws_security_group.test",
    )


def test_public_ssh_is_blocked():
    change = make_change(
        "aws_security_group",
        None,
        {
            "ingress": [
                {
                    "protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["0.0.0.0/0"],
                }
            ]
        },
    )

    findings = analyze([change], TEST_POLICY)

    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert findings[0].hard_block is True
    assert findings[0].risk_points == 40


def test_public_https_requires_approval():
    change = make_change(
        "aws_security_group",
        None,
        {
            "ingress": [
                {
                    "protocol": "tcp",
                    "from_port": 443,
                    "to_port": 443,
                    "cidr_blocks": ["0.0.0.0/0"],
                }
            ]
        },
    )

    findings = analyze([change], TEST_POLICY)

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].hard_block is False
    assert findings[0].risk_points == 35


def test_sensitive_port_inside_range():
    change = make_change(
        "aws_security_group",
        None,
        {
            "ingress": [
                {
                    "protocol": "tcp",
                    "from_port": 20,
                    "to_port": 4000,
                    "cidr_blocks": ["0.0.0.0/0"],
                }
            ]
        },
    )

    findings = analyze([change], TEST_POLICY)

    assert len(findings) == 1
    assert findings[0].hard_block is True


def test_private_ssh_no_public_finding():
    change = make_change(
        "aws_security_group",
        None,
        {
            "ingress": [
                {
                    "protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["10.0.0.0/8"],
                }
            ]
        },
    )

    findings = analyze([change], TEST_POLICY)

    assert findings == []


def test_ipv6_public_ssh():
    change = make_change(
        "aws_security_group",
        None,
        {
            "ingress": [
                {
                    "protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "ipv6_cidr_blocks": ["::/0"],
                }
            ]
        },
    )

    findings = analyze([change], TEST_POLICY)

    assert len(findings) == 1
    assert findings[0].hard_block is True


def test_standalone_ingress_rule():
    change = make_change(
        "aws_vpc_security_group_ingress_rule",
        None,
        {
            "ip_protocol": "tcp",
            "from_port": 3389,
            "to_port": 3389,
            "cidr_ipv4": "0.0.0.0/0",
        },
    )

    findings = analyze([change], TEST_POLICY)

    assert len(findings) == 1
    assert findings[0].hard_block is True


def test_existing_rule_not_reported():
    rule = {
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22,
        "cidr_blocks": ["0.0.0.0/0"],
    }

    change = make_change(
        "aws_security_group",
        {"ingress": [rule]},
        {"ingress": [rule]},
    )

    findings = analyze([change], TEST_POLICY)

    assert findings == []


def test_policy_can_disable_hard_block():
    policy = {
        **TEST_POLICY,
        "hard_block_sensitive_ports": False,
    }

    change = make_change(
        "aws_vpc_security_group_ingress_rule",
        None,
        {
            "ip_protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "cidr_ipv4": "0.0.0.0/0",
        },
    )

    findings = analyze([change], policy)

    assert len(findings) == 1
    assert findings[0].hard_block is False
    assert findings[0].risk_points == 35


def test_legacy_egress_rule_ignored():
    change = make_change(
        "aws_security_group_rule",
        None,
        {
            "type": "egress",
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "cidr_blocks": ["0.0.0.0/0"],
        },
    )

    findings = analyze([change], TEST_POLICY)

    assert findings == []


def test_all_protocols_blocked():
    change = make_change(
        "aws_vpc_security_group_ingress_rule",
        None,
        {
            "ip_protocol": "-1",
            "cidr_ipv4": "0.0.0.0/0",
        },
    )

    findings = analyze([change], TEST_POLICY)

    assert len(findings) == 1
    assert findings[0].hard_block is True

from src.parser import parse_tfplan


def test_parser_detects_replacement():
    plan = {
        "resource_changes": [
            {
                "address": "aws_instance.demo",
                "type": "aws_instance",
                "change": {
                    "actions": ["delete", "create"],
                    "before": {"instance_type": "t3.micro"},
                    "after": {"instance_type": "t3.small"},
                },
            }
        ]
    }
    changes = parse_tfplan(plan)
    assert changes[0].replacement is True

# Build by Imran Haider

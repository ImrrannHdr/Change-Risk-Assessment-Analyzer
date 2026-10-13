from typing import Any

from src.common.models import Change


def parse_tfplan(plan: dict[str, Any]) -> list[Change]:
    """Convert Terraform plan JSON into a small, stable internal change model."""
    changes: list[Change] = []

    for item in plan.get("resource_changes", []):
        change = item.get("change", {})
        actions = change.get("actions", [])
        replacement = "delete" in actions and "create" in actions

        changes.append(
            Change(
                address=item.get("address", "unknown"),
                resource_type=item.get("type", "unknown"),
                actions=actions,
                before=change.get("before"),
                after=change.get("after"),
                replacement=replacement,
            )
        )

    return changes

# Build by Imran Haider

"""Stage 3G: detect route/association changes that invalidate snapshot comparisons.

Read-only plan evidence. This is a conservative guard, not a projected-route simulator.
"""
from __future__ import annotations
from typing import Any


def _known_table(value: Any) -> str | None:
    return value if isinstance(value, str) and value.startswith('rtb-') else None


def association_plan_conflicts(change: dict, route_changes: list[dict]) -> dict:
    """Identify related simultaneous route changes for an association transition.

    Conservative behaviour: if a proposed route change has an unknown table ID,
    we cannot exclude its relevance, so the comparison must be flagged.
    """
    if change.get('resource_type') != 'aws_route_table_association':
        return {'status': 'NOT_APPLICABLE', 'conflicts': []}
    before = change.get('before') or {}
    after = change.get('after') or {}
    old_table = _known_table(before.get('route_table_id'))
    new_table = _known_table(after.get('route_table_id'))
    touched = {x for x in (old_table, new_table) if x}
    conflicts = []
    for record in route_changes:
        typ = record.get('resource_type')
        if typ == 'aws_route':
            old = _known_table((record.get('before') or {}).get('route_table_id'))
            new = _known_table((record.get('after') or {}).get('route_table_id'))
            tables = {x for x in (old, new) if x}
            unknown = not (old and new)  # new/delete actions often have only one side
            relevant = bool(touched.intersection(tables)) or unknown
        elif typ == 'aws_route_table':
            old = _known_table(record.get('route_table_id_before'))
            new = _known_table(record.get('route_table_id_after'))
            tables = {x for x in (old, new) if x}
            unknown = not (old and new)
            relevant = bool(touched.intersection(tables)) or unknown
        elif typ == 'aws_main_route_table_association':
            # Changes to the VPC main table can affect implicit fallbacks.
            relevant = True
            tables = set()
            unknown = True
        else:
            continue
        if relevant:
            conflicts.append({
                'resource': record.get('resource'),
                'resource_type': typ,
                'lifecycle_action': record.get('lifecycle_action'),
                'known_route_table_ids': sorted(tables),
                'table_identity_incomplete': unknown,
            })
    return {
        'status': 'POTENTIAL_CONFLICT' if conflicts else 'NO_CONFLICT_OBSERVED',
        'conflicts': conflicts[:25],
        'conflict_count': len(conflicts),
        'context_complete': False,
        'note': 'Conservative plan-only guard; no proposed route-set simulation',
    }

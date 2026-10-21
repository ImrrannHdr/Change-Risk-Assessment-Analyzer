"""Production-safe, read-only report generator. No Terraform apply or AWS writes."""
import argparse
import json
from pathlib import Path

from src.analyzers.route_changes import detect_route_changes
from src.context.route_impact import assess_route_change


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--plan', default='tfplan.json')
    p.add_argument('--region', default='ap-southeast-2')
    p.add_argument('--output', default='stage3bc-report.json')
    args = p.parse_args()
    plan = json.loads(Path(args.plan).read_text(encoding='utf-8'))
    reports = []
    for change in detect_route_changes(plan):
        try:
            impact = assess_route_change(change, region=args.region)
        except Exception as exc:
            impact = {'status': 'CONTEXT_ERROR', 'context_complete': False,
                      'error_type': type(exc).__name__, 'message': str(exc)}
        reports.append({'change': change, 'impact': impact})
        print(f"{change['resource']}: {change['lifecycle_action']} -> {impact['status']}")
    Path(args.output).write_text(json.dumps(reports, indent=2, default=str), encoding='utf-8')
    print(f'Reported {len(reports)} route change(s) in {args.output} (sensitive infrastructure data: keep private)')


if __name__ == '__main__':
    main()

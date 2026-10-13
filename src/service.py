from src.analyzers import cost, iam, network, rollback
from src.parser import parse_tfplan
from src.risk_engine import evaluate


def analyze_plan(plan: dict, environment: str = "dev"):
    changes = parse_tfplan(plan)
    findings = []
    findings.extend(iam.analyze(changes))
    findings.extend(network.analyze(changes))
    findings.extend(cost.analyze(changes))
    findings.extend(rollback.analyze(changes))
    return evaluate(findings, environment=environment)

# Build by Imran Haider

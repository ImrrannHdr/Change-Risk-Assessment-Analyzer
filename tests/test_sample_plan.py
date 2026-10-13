from pathlib import Path

import yaml

from src.service import analyze_plan


def test_sample_plan_blocks():
    plan = yaml.safe_load(Path("samples/sample_tfplan.yaml").read_text())
    result = analyze_plan(plan, environment="prod")
    assert result.decision == "BLOCK"
    categories = {f.category for f in result.findings}
    assert "INTERNET_EXPOSURE" in categories
    assert "IAM_WILDCARD" in categories

# Build by Imran Haider

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Change:
    address: str
    resource_type: str
    actions: list[str]
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    replacement: bool = False


@dataclass
class Finding:
    category: str
    severity: str
    risk_points: int
    resource: str
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)
    hard_block: bool = False


@dataclass
class AnalysisResult:
    risk_score: int
    risk_level: str
    decision: str
    findings: list[Finding]

# Build by Imran Haider

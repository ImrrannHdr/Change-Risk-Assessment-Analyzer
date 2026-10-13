import json
import sys
from dataclasses import asdict
from pathlib import Path

import yaml

from src.service import analyze_plan


def _load_plan(path: Path) -> dict:
    if path.suffix.lower() in {".yaml", ".yml"}:
        return yaml.safe_load(path.read_text())
    return json.loads(path.read_text())


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python -m src.cli <tfplan.json|yaml> [environment]")
        return 2

    path = Path(sys.argv[1])
    environment = sys.argv[2] if len(sys.argv) > 2 else "dev"
    result = analyze_plan(_load_plan(path), environment)
    print(json.dumps(asdict(result), indent=2))
    return 1 if result.decision == "BLOCK" else 0


if __name__ == "__main__":
    raise SystemExit(main())

# Build by Imran Haider

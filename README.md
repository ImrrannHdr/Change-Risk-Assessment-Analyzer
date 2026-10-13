# AWS IaC Risk Engine

A pre-deployment **AWS Change Intelligence and Blast-Radius Analysis Platform** for Terraform changes.

The project parses `terraform show -json` output, applies domain-specific analyzers, produces deterministic findings, calculates an overall deployment risk score, and can be invoked by AWS Lambda/Step Functions or locally in CI.

## What it demonstrates

- Python and boto3-oriented AWS automation
- Terraform modules and serverless AWS architecture
- GitHub Actions CI/CD
- GitHub OIDC to AWS
- IAM / network / rollback risk analysis
- Deterministic policy-as-code risk scoring
- S3, Lambda, Step Functions, EventBridge, DynamoDB, CloudWatch and SNS
- Unit testing with pytest

## MVP flow

```text
GitHub PR
   |
   v
terraform plan -> terraform show -json
   |
   v
S3 plan bucket
   |
   v
EventBridge / Step Functions
   |
   +--> Parser Lambda
   +--> IAM Analyzer
   +--> Network Analyzer
   +--> Rollback Analyzer
   |
   v
Risk Engine
   |
   v
DynamoDB result + SNS alert + CI decision
```

## Quick local demo

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\\Scripts\\activate
pip install -r requirements-dev.txt
python -m src.cli samples/sample_tfplan.yaml
pytest -q
```

Expected sample result: the included fixture introduces public SSH and IAM wildcard access, so the overall decision should be **BLOCK**.

## Terraform deployment

From `terraform/environments/dev`:

```bash
terraform init
terraform plan
terraform apply
```

The module provisions the analysis platform infrastructure. In a production implementation you would also add a GitHub OIDC trust policy restricted to your exact repository/environment and wire PR result publishing to the GitHub API.

## Security model

The risk decision is deterministic. Generative AI can be added later to explain already-calculated findings, but it must not create or suppress control decisions.

## Repository structure

```text
src/                      Python parser, analyzers, risk engine and Lambda entrypoint
policies/                 Configurable risk policy
samples/                  Terraform plan fixture
terraform/                AWS infrastructure
.github/workflows/        CI workflow
 tests/                    Unit tests
 docs/                     Architecture notes
```

<!-- Build by Imran Haider -->

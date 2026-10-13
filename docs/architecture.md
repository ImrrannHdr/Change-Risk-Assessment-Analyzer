# Architecture Notes

## Purpose

The system adds a change-intelligence layer between `terraform plan` and `terraform apply`.

## Responsibility split

- **Parser**: converts Terraform JSON into a stable internal model.
- **Analyzers**: create evidence-backed domain findings.
- **Risk engine**: converts all findings into a final score and CI decision.
- **Step Functions**: orchestrates analysis in AWS.
- **GitHub Actions**: owns CI/CD and deployment gating.

## Design principle

The platform should fail closed for critical analysis failures in production, but optional features such as cost explanation or generative-AI summaries may fail open.

## Planned extensions

1. AWS Organizations / SCP attachment traversal.
2. IAM Access Analyzer `ValidatePolicy` integration.
3. AWS Config dependency graph enrichment.
4. Transit Gateway route blast-radius analysis.
5. GitHub PR Checks API publishing.
6. Historical deployment outcome feedback in DynamoDB.
7. Bedrock explanation layer that never changes policy outcomes.

<!-- Build by Imran Haider -->

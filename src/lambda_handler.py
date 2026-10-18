"""Terraform plan risk and security-group impact Lambda handler.

Input: {"bucket": "...", "key": "...", "environment": "dev"}
Full results are stored in DynamoDB; a compact response is returned to Step Functions.
"""

import json
import logging
import os
from dataclasses import asdict
from datetime import datetime, timezone
from decimal import Decimal

import boto3

from src.service import analyze_plan
from src.context.security_group_impact import analyze_all_security_group_impacts

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")


def to_dynamodb_compatible(value):
    """Convert nested floats to DynamoDB-compatible Decimals."""
    if isinstance(value, float):
        if not (float("-inf") < value < float("inf")):
            raise ValueError("Non-finite float encountered in analysis result")
        return Decimal(str(value))
    if isinstance(value, dict):
        return {key: to_dynamodb_compatible(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [to_dynamodb_compatible(item) for item in value]
    return value


def sanitize_security_group_impacts(impacts):
    """Keep reporting fields, not raw Terraform before/after structures."""
    records = []
    for change in impacts:
        impact = change.get("impact") or {}
        records.append({
            "resource": change.get("resource"),
            "resource_type": change.get("resource_type"),
            "direction": change.get("direction"),
            "classification": change.get("classification"),
            "terraform_actions": change.get("terraform_actions", []),
            "analysis_complete": change.get("analysis_complete", False),
            "possible_impact": change.get("possible_impact"),
            "unknown_paths": change.get("unknown_paths", []),
            "sensitive_paths": change.get("sensitive_paths", []),
            "lifecycle_action": change.get("lifecycle_action"),
            "impact": {
                "status": impact.get("status", "UNRESOLVED"),
                "security_group_id": (
                    impact.get("security_group_id")
                    or change.get("security_group_id")
                ),
                "context_complete": impact.get("context_complete", False),
                "message": impact.get("message"),
                "existing_dependencies": impact.get("existing_dependencies"),
                "planned_dependencies": impact.get("planned_dependencies"),
            },
        })
    return records


def summarize_security_group_impacts(impacts):
    summary = {
        "total_changes": len(impacts),
        "resolved": 0,
        "unresolved": 0,
        "context_errors": 0,
        "lifecycle_changes": 0,
        "not_applicable": 0,
        "incomplete": 0,
    }
    for change in impacts:
        impact = change["impact"]
        status = impact["status"]
        if status == "RESOLVED":
            summary["resolved"] += 1
        elif status == "CONTEXT_ERROR":
            summary["context_errors"] += 1
        elif status == "LIFECYCLE_CHANGE":
            summary["lifecycle_changes"] += 1
        elif status == "NOT_APPLICABLE":
            summary["not_applicable"] += 1
        else:
            summary["unresolved"] += 1
        if (not change["analysis_complete"] or not impact["context_complete"]):
            summary["incomplete"] += 1
    return summary


def lambda_handler(event, context):
    # Compatible with the existing EventBridge -> Step Functions input transformer.
    bucket = event["bucket"]
    key = event["key"]
    environment = event.get("environment", "dev")
    analysis_id = event.get("analysis_id") or context.aws_request_id
    region = os.environ.get("AWS_REGION", "ap-southeast-2")
    enable_context = os.environ.get("ENABLE_CONTEXT_ANALYSIS", "false").lower() == "true"
    table_name = os.environ.get("ANALYSIS_RESULTS_TABLE")
    if not table_name:
        raise RuntimeError("ANALYSIS_RESULTS_TABLE environment variable is not set")

    logger.info(
        "[RISK-ANALYZER] Started analysis_id=%s bucket=%s key=%s context_enabled=%s",
        analysis_id, bucket, key, enable_context,
    )

    parts = key.split("/")
    repository = None
    commit_sha = None
    if len(parts) >= 4 and parts[0] == "github":
        repository = f"{parts[1]}/{parts[2]}"
        commit_sha = parts[3].removesuffix(".json")

    response = s3.get_object(Bucket=bucket, Key=key)
    plan = json.loads(response["Body"].read())

    # Preserve existing IAM / network / cost / rollback scoring.
    result = analyze_plan(
        plan=plan,
        environment=environment,
        enable_context=enable_context,
        region=region,
    )
    findings = asdict(result)["findings"]

    if enable_context:
        impact_results = analyze_all_security_group_impacts(plan=plan, region=region)
        impacts = sanitize_security_group_impacts(impact_results)
    else:
        impacts = []

    summary = summarize_security_group_impacts(impacts)
    logger.info(
        "[SG-IMPACT] total=%d resolved=%d errors=%d incomplete=%d",
        summary["total_changes"], summary["resolved"],
        summary["context_errors"], summary["incomplete"],
    )
    for change in impacts:
        logger.info(
            "[SG-IMPACT] resource=%s type=%s status=%s sg=%s",
            change["resource"], change["classification"],
            change["impact"]["status"], change["impact"]["security_group_id"],
        )

    item = {
        "analysis_id": analysis_id,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "decision": result.decision,
        "findings": findings,
        "finding_count": len(findings),
        "security_group_impacts": impacts,
        "security_group_impact_summary": summary,
        "security_group_change_count": len(impacts),
        "security_group_impact_enabled": enable_context,
        "source_key": key,
        "environment": environment,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if repository:
        item["repository"] = repository
    if commit_sha:
        item["commit_sha"] = commit_sha

    # Check approximation before DynamoDB's 400 KiB hard limit.
    # No silent truncation of impact evidence.
    approximate_bytes = len(json.dumps(item, default=str).encode("utf-8"))
    if approximate_bytes >= 350_000:
        raise ValueError(
            "Analysis evidence may exceed DynamoDB item limit; "
            "move detailed findings to S3 before retrying"
        )

    try:
        dynamodb.Table(table_name).put_item(Item=to_dynamodb_compatible(item))
    except Exception:
        logger.exception("[DYNAMODB] Failed to save analysis_id=%s", analysis_id)
        raise

    logger.info(
        "[DYNAMODB] Stored analysis_id=%s findings=%d sg_impacts=%d decision=%s",
        analysis_id, len(findings), len(impacts), result.decision,
    )

    # Keep Step Functions output compact to avoid the 256 KiB state payload cap.
    # The complete evidence is saved in DynamoDB for GitHub Actions reporting.
    step_functions_result = {
        "analysis_id": analysis_id,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "decision": result.decision,
        "finding_count": len(findings),
        "security_group_change_count": len(impacts),
        "security_group_impact_summary": summary,
        "security_group_impact_enabled": enable_context,
        "environment": environment,
        "source_key": key,
    }
    if repository:
        step_functions_result["repository"] = repository
    if commit_sha:
        step_functions_result["commit_sha"] = commit_sha

    topic_arn = os.environ.get("RISK_ALERT_TOPIC_ARN")
    if topic_arn and result.decision == "BLOCK":
        sns.publish(
            TopicArn=topic_arn,
            Subject="Terraform change blocked",
            Message=json.dumps(step_functions_result, indent=2),
        )

    logger.info("[RISK-ANALYZER] Finished analysis_id=%s", analysis_id)
    return step_functions_result


# Built by Imran Haider



"""Terraform plan risk and independent security-group impact Lambda handler.

Input: {"bucket": "...", "key": "...", "environment": "dev"}
Detailed results are stored in DynamoDB; compact results go to Step Functions.
Requires the updated src/service.py that accepts impact_sink.
"""

import json
import logging
import math
import os
from dataclasses import asdict
from datetime import datetime, timezone
from decimal import Decimal

import boto3

from src.service import analyze_plan
from src.context.impact_orchestrator import summarize_sg_impacts

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")


def to_dynamodb_compatible(value):
    """Recursively convert finite floats into DynamoDB-compatible Decimals."""
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Non-finite float encountered in analysis result")
        return Decimal(str(value))
    if isinstance(value, dict):
        return {key: to_dynamodb_compatible(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [to_dynamodb_compatible(item) for item in value]
    return value

def sanitize_security_group_impacts(impacts):
    """Persist bounded SG reporting fields without full Terraform before/after plans."""
    records = []
    for change in impacts:
        impact = change.get('impact') or {}
        safe_impact = {
            'status': impact.get('status', 'UNRESOLVED'),
            'security_group_id': impact.get('security_group_id') or change.get('security_group_id'),
            'security_group_address': impact.get('security_group_address'),
            'context_complete': impact.get('context_complete', False),
            'message': impact.get('message'),
            'existing_dependencies': impact.get('existing_dependencies'),
            'planned_dependencies': impact.get('planned_dependencies'),
        }
        # Preserve Stage 2A lifecycle investigation.
        for key in ('lifecycle_action', 'old_security_group_id', 'new_security_group_id',
                    'impact_category', 'attachment_transitions'):
            if key in impact:
                safe_impact[key] = impact[key]
        item = {
            'resource': change.get('resource'),
            'resource_type': change.get('resource_type'),
            'direction': change.get('direction'),
            'classification': change.get('classification'),
            'terraform_actions': change.get('terraform_actions', []),
            'analysis_complete': change.get('analysis_complete', False),
            'possible_impact': change.get('possible_impact'),
            'unknown_paths': change.get('unknown_paths', []),
            'sensitive_paths': change.get('sensitive_paths', []),
            'lifecycle_action': change.get('lifecycle_action'),
            'impact': safe_impact,
        }
        if 'permission_delta' in change:
            delta = change['permission_delta']
            item['permission_delta'] = {
                key: delta.get(key)
                for key in ('lifecycle_action', 'permission_effect',
                            'added_permissions', 'removed_permissions',
                            'permission_comparison_complete', 'message')
            }
        if 'rule_assessment' in change:
            item['rule_assessment'] = change['rule_assessment']
        records.append(item)
    return records


def lambda_handler(event, context):
    # 1. Read Step Functions input; preserve the existing event contract.
    bucket = event["bucket"]
    key = event["key"]
    environment = event.get("environment", "dev")
    analysis_id = event.get("analysis_id") or context.aws_request_id
    region = os.environ.get("AWS_REGION", "ap-southeast-2")
    enable_context = (
        os.environ.get("ENABLE_CONTEXT_ANALYSIS", "false").lower() == "true"
    )
    table_name = os.environ.get("ANALYSIS_RESULTS_TABLE")
    if not table_name:
        raise RuntimeError("ANALYSIS_RESULTS_TABLE environment variable is not set")

    logger.info(
        "[RISK-ANALYZER] Started analysis_id=%s bucket=%s key=%s context_enabled=%s",
        analysis_id, bucket, key, enable_context,
    )

    # 2. Recover repository/commit metadata from the uploaded S3 object key.
    parts = key.split("/")
    repository = None
    commit_sha = None
    if len(parts) >= 4 and parts[0] == "github":
        repository = f"{parts[1]}/{parts[2]}"
        commit_sha = parts[3].removesuffix(".json")

    # 3. Download and parse the Terraform JSON plan.
    logger.info("[S3] Downloading Terraform plan")
    response = s3.get_object(Bucket=bucket, Key=key)
    plan = json.loads(response["Body"].read())
    logger.info("[S3] Terraform plan loaded successfully")

    # 4. Use a NEW list per invocation. The updated service.py will fill it
    # independently of whether network.py generates INTERNET_EXPOSURE findings.
    raw_impacts = []
    logger.info("[ANALYSIS] Starting plan and SG impact analysis")
    result = analyze_plan(
        plan,
        environment=environment,
        enable_context=enable_context,
        region=region,
        impact_sink=raw_impacts,
    )
    findings = asdict(result)["findings"]

    # IMPORTANT: Do NOT also call analyze_all_security_group_impacts() here.
    # That would duplicate impact analysis and AWS resource discovery.
    impacts = sanitize_security_group_impacts(raw_impacts)
    summary = summarize_sg_impacts(raw_impacts)

    logger.info(
            "[SG-IMPACT] total=%d lifecycle=%d ingress=%d "
            "egress=%d resolved=%d unresolved=%d "
            "errors=%d incomplete=%d not_assessed=%d",
            summary["total_sg_change_records"],
            summary["whole_sg_lifecycle_changes"],
            summary["ingress_rule_changes"],
            summary["egress_rule_changes"],
            summary["resolved_rule_impacts"],
            summary["unresolved_rule_impacts"],
            summary["context_analysis_errors"],
            summary["incomplete_context_assessments"],
            summary["not_assessed_changes"],
    )
    for change in impacts:
        logger.info(
            "[SG-IMPACT] resource=%s classification=%s status=%s sg=%s",
            change["resource"],
            change["classification"],
            change["impact"]["status"],
            change["impact"]["security_group_id"],
        )

    # 5. Persist the risk output and independent impact evidence to DynamoDB.
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

    # Guard against DynamoDB's 400 KiB item limit without silent truncation.
    approximate_bytes = len(json.dumps(item, default=str).encode("utf-8"))
    if approximate_bytes >= 350_000:
        raise ValueError(
            "Analysis evidence may exceed DynamoDB item limit; "
            "move detailed findings to S3 before retrying"
        )

    logger.info("[DYNAMODB] Writing result to table=%s", table_name)
    try:
        dynamodb.Table(table_name).put_item(Item=to_dynamodb_compatible(item))
    except Exception:
        logger.exception("[DYNAMODB] Failed to save analysis_id=%s", analysis_id)
        raise

    logger.info(
        "[DYNAMODB] Stored analysis_id=%s findings=%d sg_impacts=%d decision=%s",
        analysis_id, len(findings), len(impacts), result.decision,
    )

    # 6. Keep the Step Functions response compact. Detailed evidence is in DynamoDB.
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

    # 7. Preserve existing SNS behaviour for BLOCK decisions.
    topic_arn = os.environ.get("RISK_ALERT_TOPIC_ARN")
    if topic_arn and result.decision == "BLOCK":
        sns.publish(
            TopicArn=topic_arn,
            Subject="Terraform change blocked",
            Message=json.dumps(step_functions_result, indent=2),
        )

    logger.info("[RISK-ANALYZER] Returning result to Step Functions: %s",
                json.dumps(step_functions_result, default=str))
    return step_functions_result





import json
import os
import logging

from dataclasses import asdict
from decimal import Decimal
from datetime import datetime, timezone

import boto3

from src.service import analyze_plan
from src.context.security_group_impact import (
    analyze_all_security_group_impacts,
)


# ============================================================
# AWS Clients
# ============================================================

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ============================================================
# DynamoDB Serialization
# ============================================================

def to_dynamodb_compatible(value):
    """
    Convert Python values into DynamoDB-compatible types.
    """

    if isinstance(value, float):
        return Decimal(str(value))

    if isinstance(value, dict):
        return {
            key: to_dynamodb_compatible(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [
            to_dynamodb_compatible(item)
            for item in value
        ]

    return value


# ============================================================
# Security Group Impact Sanitization
# ============================================================

def sanitize_security_group_impacts(impacts):
    """
    Build a reporting-friendly security group impact list.

    Excludes raw Terraform before/after values.

    Retains:
      - SG change classification
      - Terraform actions
      - Possible impact
      - AWS resource discovery evidence
      - Investigation status
      - Context completeness
    """

    sanitized = []

    for change in impacts:

        impact = change.get("impact") or {}

        record = {
            "resource": change.get("resource"),
            "resource_type": change.get("resource_type"),
            "classification": change.get("classification"),
            "direction": change.get("direction"),
            "terraform_actions": change.get(
                "terraform_actions", []
            ),
            "analysis_complete": change.get(
                "analysis_complete", False
            ),
            "possible_impact": change.get(
                "possible_impact"
            ),
            "unknown_paths": change.get(
                "unknown_paths", []
            ),
            "sensitive_paths": change.get(
                "sensitive_paths", []
            ),
            "impact": {
                "status": impact.get(
                    "status", "UNRESOLVED"
                ),
                "security_group_id": (
                    impact.get("security_group_id")
                    or change.get("security_group_id")
                ),
                "context_complete": impact.get(
                    "context_complete", False
                ),
                "message": impact.get("message"),
                "existing_dependencies": impact.get(
                    "existing_dependencies"
                ),
                "planned_dependencies": impact.get(
                    "planned_dependencies"
                ),
            },
        }

        if change.get("lifecycle_event"):
            record["lifecycle_event"] = True

        if change.get("lifecycle_action"):
            record["lifecycle_action"] = change[
                "lifecycle_action"
            ]

        if change.get("replace_paths"):
            record["replace_paths"] = change[
                "replace_paths"
            ]

        sanitized.append(record)

    return sanitized


# ============================================================
# Security Group Impact Summary
# ============================================================

def summarize_security_group_impacts(impacts):
    """
    Generate summary statistics for DynamoDB
    and GitHub Actions reporting.

    Context incomplete is not treated as zero impact.
    """

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

        impact = change.get("impact") or {}
        status = impact.get("status", "UNRESOLVED")

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

        if (
            not change.get("analysis_complete", False)
            or not impact.get("context_complete", False)
        ):
            summary["incomplete"] += 1

    return summary


# ============================================================
# Lambda Handler
# ============================================================

def lambda_handler(event, context):

    # --------------------------------------------------------
    # STEP 1: Read Input
    # --------------------------------------------------------

    bucket = event["bucket"]
    key = event["key"]

    environment = event.get("environment", "dev")

    analysis_id = (
        event.get("analysis_id")
        or context.aws_request_id
    )

    source_key = key

    region = os.environ.get(
        "AWS_REGION", "ap-southeast-2"
    )

    logger.info(
        "[RISK-ANALYZER] Starting risk assessment | "
        "analysis_id=%s | environment=%s | source_key=%s",
        analysis_id,
        environment,
        source_key,
    )

    # --------------------------------------------------------
    # STEP 2: Extract GitHub Metadata
    # --------------------------------------------------------

    repository = None
    commit_sha = None

    parts = key.split("/")

    if len(parts) >= 4 and parts[0] == "github":
        repository = f"{parts[1]}/{parts[2]}"
        commit_sha = parts[3].removesuffix(".json")

    # --------------------------------------------------------
    # STEP 3: Retrieve Terraform Plan
    # --------------------------------------------------------

    response = s3.get_object(
        Bucket=bucket,
        Key=key,
    )

    plan = json.loads(
        response["Body"].read()
    )

    logger.info(
        "[RISK-ANALYZER] Terraform plan loaded | "
        "resource_changes=%s",
        len(plan.get("resource_changes", [])),
    )

    # --------------------------------------------------------
    # STEP 4: Context Analysis Configuration
    # --------------------------------------------------------

    enable_context = (
        os.environ.get(
            "ENABLE_CONTEXT_ANALYSIS",
            "false",
        ).lower() == "true"
    )

    logger.info(
        "[RISK-ANALYZER] Context analysis enabled: %s",
        enable_context,
    )

    # --------------------------------------------------------
    # STEP 5: Existing Risk Assessment
    # --------------------------------------------------------

    result = analyze_plan(
        plan=plan,
        environment=environment,
        enable_context=enable_context,
        region=region,
    )

    payload = asdict(result)
    payload["analysis_id"] = analysis_id

    logger.info(
        "[RISK-ANALYZER] Risk analysis complete | "
        "risk_score=%s | risk_level=%s | "
        "decision=%s | findings=%s",
        result.risk_score,
        result.risk_level,
        result.decision,
        len(result.findings),
    )

    # --------------------------------------------------------
    # STEP 6: Generalised Security Group Impact Analysis
    # --------------------------------------------------------

    sg_impacts = []

    if enable_context:

        logger.info(
            "[SG-IMPACT] Starting investigation of "
            "all supported security group changes"
        )

        sg_impacts = analyze_all_security_group_impacts(
            plan=plan,
            region=region,
        )

        logger.info(
            "[SG-IMPACT] Investigation completed | "
            "changes=%s",
            len(sg_impacts),
        )

    else:
        logger.info(
            "[SG-IMPACT] Context analysis disabled. "
            "Impact investigation skipped."
        )

    # Strip raw Terraform before/after objects.
    safe_impacts = sanitize_security_group_impacts(
        sg_impacts
    )

    impact_summary = summarize_security_group_impacts(
        safe_impacts
    )

    payload["security_group_impacts"] = safe_impacts

    payload["security_group_impact_summary"] = (
        impact_summary
    )

    payload["security_group_change_count"] = len(
        safe_impacts
    )

    # Explicitly distinguish disabled context analysis
    # from a plan containing zero security group changes.
    payload["security_group_impact_enabled"] = enable_context

    # --------------------------------------------------------
    # STEP 7: Log Individual Security Group Impacts
    # --------------------------------------------------------

    for change in safe_impacts:

        impact = change.get("impact") or {}

        existing = (
            impact.get("existing_dependencies") or {}
        )

        ec2_instances = existing.get(
            "ec2_instances"
        )

        logger.info(
            "[SG-IMPACT] Resource=%s | "
            "classification=%s | direction=%s | "
            "sg_id=%s | status=%s | "
            "affected_ec2=%s | context_complete=%s",
            change.get("resource"),
            change.get("classification"),
            change.get("direction"),
            impact.get("security_group_id"),
            impact.get("status"),
            (
                ec2_instances
                if ec2_instances is not None
                else "UNKNOWN"
            ),
            impact.get("context_complete"),
        )

    logger.info(
        "[SG-IMPACT] Summary: %s",
        json.dumps(impact_summary),
    )

    # --------------------------------------------------------
    # STEP 8: Validate Existing Risk Findings
    # --------------------------------------------------------

    for finding in payload["findings"]:

        blast_radius = (
            (finding.get("evidence") or {})
            .get("blast_radius")
        )

        logger.info(
            "[RISK-ANALYZER] Finding | "
            "category=%s | resource=%s | "
            "blast_radius_status=%s",
            finding.get("category"),
            finding.get("resource"),
            (
                blast_radius.get("status")
                if isinstance(blast_radius, dict)
                else "NOT_AVAILABLE"
            ),
        )

    # --------------------------------------------------------
    # STEP 9: Prepare DynamoDB Item
    # --------------------------------------------------------

    item = {
        "analysis_id": analysis_id,

        # Existing risk results
        "risk_score": payload["risk_score"],
        "risk_level": payload["risk_level"],
        "decision": payload["decision"],

        # Existing detailed findings
        "findings": payload["findings"],
        "finding_count": len(payload["findings"]),

        # NEW: Security group impact results
        "security_group_impacts": safe_impacts,
        "security_group_impact_summary": impact_summary,
        "security_group_change_count": len(
            safe_impacts
        ),
        "security_group_impact_enabled": enable_context,

        # Metadata
        "source_key": source_key,
        "environment": environment,
        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    if repository:
        item["repository"] = repository

    if commit_sha:
        item["commit_sha"] = commit_sha

    # --------------------------------------------------------
    # STEP 10: Convert DynamoDB Data Types
    # --------------------------------------------------------

    item = to_dynamodb_compatible(item)

    # --------------------------------------------------------
    # STEP 11: Persist Findings and Impacts
    # --------------------------------------------------------

    table_name = os.environ.get(
        "ANALYSIS_RESULTS_TABLE"
    )

    if not table_name:
        raise RuntimeError(
            "ANALYSIS_RESULTS_TABLE environment "
            "variable is not configured"
        )

    # Check the response size before persisting because
    # Step Functions also has a 256 KiB payload limit.
    # This is an early size guard, not an exact DynamoDB
    # storage-size calculation.
    payload_size = len(
        json.dumps(
            payload,
            default=str,
        ).encode("utf-8")
    )

    if payload_size >= 220_000:
        raise ValueError(
            "Analysis payload exceeds the configured "
            "inline response safety limit. "
            "Store detailed findings in S3 instead."
        )

    table = dynamodb.Table(table_name)

    try:
        table.put_item(
            Item=item
        )

        logger.info(
            "[DYNAMODB] Write successful | "
            "table=%s | analysis_id=%s | "
            "findings_saved=%s | sg_impacts_saved=%s",
            table_name,
            analysis_id,
            len(item["findings"]),
            len(item["security_group_impacts"]),
        )

    except Exception:

        logger.exception(
            "[DYNAMODB] Write failed | "
            "analysis_id=%s",
            analysis_id,
        )

        raise

    # --------------------------------------------------------
    # STEP 12: SNS Notification For Blocked Changes
    # --------------------------------------------------------

    topic_arn = os.environ.get(
        "RISK_ALERT_TOPIC_ARN"
    )

    if topic_arn and result.decision == "BLOCK":

        logger.info(
            "[SNS] Publishing blocked-change notification"
        )

        sns.publish(
            TopicArn=topic_arn,
            Subject="Terraform change blocked",
            Message=json.dumps(
                payload,
                indent=2,
                default=str,
            ),
        )

    # --------------------------------------------------------
    # STEP 13: Return Enriched Result to Step Functions
    # --------------------------------------------------------

    logger.info(
        "[RISK-ANALYZER] Assessment finished | "
        "analysis_id=%s | decision=%s | "
        "sg_changes=%s",
        analysis_id,
        result.decision,
        len(safe_impacts),
    )

    return payload


# Built by Imran Haider

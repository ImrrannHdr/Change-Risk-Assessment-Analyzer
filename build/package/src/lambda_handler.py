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
    """Store reporting fields without duplicating full Terraform before/after data."""
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
                "security_group_address": impact.get("security_group_address"),
                "context_complete": impact.get("context_complete", False),
                "message": impact.get("message"),
                "existing_dependencies": impact.get("existing_dependencies"),
                "planned_dependencies": impact.get("planned_dependencies"),
            },
        })
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
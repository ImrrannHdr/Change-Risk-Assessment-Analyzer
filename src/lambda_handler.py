
import json
import os
import logging
from dataclasses import asdict
from decimal import Decimal
from datetime import datetime, timezone

import boto3

from src.service import analyze_plan


# ---------------------------------------
# AWS Clients
# ---------------------------------------

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ---------------------------------------
# DynamoDB Serialization
# ---------------------------------------

def to_dynamodb_compatible(value):
    """
    Recursively convert Python floats into Decimal
    values supported by DynamoDB.

    Preserve dictionaries, lists, booleans and None.
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


# ---------------------------------------
# Lambda Handler
# ---------------------------------------

def lambda_handler(event, context):

    bucket = event["bucket"]
    key = event["key"]

    environment = event.get("environment", "dev")
    analysis_id = (
        event.get("analysis_id")
        or context.aws_request_id
    )

    source_key = key

    logger.info(
        "Starting risk assessment | analysis_id=%s | "
        "environment=%s | source_key=%s",
        analysis_id,
        environment,
        source_key,
    )

    # ---------------------------------------
    # Extract GitHub Metadata
    # ---------------------------------------

    repository = None
    commit_sha = None

    parts = key.split("/")

    if len(parts) >= 4 and parts[0] == "github":
        repository = f"{parts[1]}/{parts[2]}"
        commit_sha = parts[3].removesuffix(".json")

    # ---------------------------------------
    # Retrieve Terraform Plan
    # ---------------------------------------

    response = s3.get_object(
        Bucket=bucket,
        Key=key,
    )

    plan = json.loads(
        response["Body"].read()
    )

    # ---------------------------------------
    # Context Analysis Configuration
    # ---------------------------------------

    enable_context = (
        os.environ.get(
            "ENABLE_CONTEXT_ANALYSIS",
            "false",
        ).lower() == "true"
    )

    logger.info(
        "Context analysis enabled: %s",
        enable_context,
    )

    # ---------------------------------------
    # Execute Risk Analysis
    # ---------------------------------------

    result = analyze_plan(
        plan=plan,
        environment=environment,
        enable_context=enable_context,
        region=os.environ.get(
            "AWS_REGION",
            "ap-southeast-2",
        ),
    )

    # Convert analysis result to dictionary
    payload = asdict(result)

    payload["analysis_id"] = analysis_id

    # ---------------------------------------
    # Prepare DynamoDB Item
    # ---------------------------------------

    item = {
        "analysis_id": analysis_id,
        "risk_score": payload["risk_score"],
        "risk_level": payload["risk_level"],
        "decision": payload["decision"],

        # NEW: Persist complete findings
        "findings": payload["findings"],

        "finding_count": len(payload["findings"]),
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

    # Convert any floating-point values to Decimal
    item = to_dynamodb_compatible(item)

    # ---------------------------------------
    # Validate Context Evidence
    # ---------------------------------------

    logger.info(
        "Analysis completed | risk_score=%s | "
        "risk_level=%s | decision=%s | findings=%s",
        result.risk_score,
        result.risk_level,
        result.decision,
        len(result.findings),
    )

    for finding in payload["findings"]:
        blast_radius = (
            finding.get("evidence", {})
            .get("blast_radius")
        )

        logger.info(
            "Finding | category=%s | resource=%s | "
            "blast_radius_status=%s",
            finding.get("category"),
            finding.get("resource"),
            (
                blast_radius.get("status")
                if isinstance(blast_radius, dict)
                else "NOT_AVAILABLE"
            ),
        )

    # ---------------------------------------
    # Store Complete Analysis in DynamoDB
    # ---------------------------------------

    table_name = os.environ.get(
        "ANALYSIS_RESULTS_TABLE"
    )

    if not table_name:
        raise RuntimeError(
            "ANALYSIS_RESULTS_TABLE environment "
            "variable is not configured"
        )

    table = dynamodb.Table(table_name)

    # Fail visibly rather than silently discard findings
    # if DynamoDB persistence fails.
    try:
        table.put_item(
            Item=item
        )

        logger.info(
            "DynamoDB write successful | "
            "table=%s | analysis_id=%s | "
            "findings_saved=%s",
            table_name,
            analysis_id,
            len(item["findings"]),
        )

    except Exception:
        logger.exception(
            "DynamoDB write failed | analysis_id=%s",
            analysis_id,
        )
        raise

    # ---------------------------------------
    # Publish SNS Notification for BLOCK
    # ---------------------------------------

    topic_arn = os.environ.get(
        "RISK_ALERT_TOPIC_ARN"
    )

    if topic_arn and result.decision == "BLOCK":

        logger.info(
            "Publishing blocked-change notification"
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

    # ---------------------------------------
    # Return Result to Step Functions
    # ---------------------------------------

    return payload


# Built by Imran Haider

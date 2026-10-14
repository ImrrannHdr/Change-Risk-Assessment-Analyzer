
import json
import os
from dataclasses import asdict

import boto3

from src.service import analyze_plan

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")


def lambda_handler(event, context):
    bucket = event["bucket"]
    key = event["key"]
    environment = event.get("environment", "dev")
    analysis_id = event.get("analysis_id") or context.aws_request_id

    source_key = key

    repository = None
    commit_sha = None

    parts = key.split("/")

    if len(parts) >= 4 and parts[0] == "github":
        repository = f"{parts[1]}/{parts[2]}"
        commit_sha = parts[3].removesuffix(".json")

    # Retrieve Terraform plan from S3
    response = s3.get_object(Bucket=bucket, Key=key)
    plan = json.loads(response["Body"].read())

    # Analyse Terraform plan
    result = analyze_plan(plan, environment)

    # Convert analysis result to dictionary
    payload = asdict(result)
    payload["analysis_id"] = analysis_id

    # Store analysis result in DynamoDB
    table_name = os.environ.get("ANALYSIS_RESULTS_TABLE")

    if table_name:
        table = dynamodb.Table(table_name)

        item = {
            "analysis_id": analysis_id,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "decision": result.decision,
            "source_key": source_key,
            "environment": environment,
        }

        if repository:
            item["repository"] = repository

        if commit_sha:
            item["commit_sha"] = commit_sha

        table.put_item(Item=item)

    # Publish SNS notification for blocked changes
    topic_arn = os.environ.get("RISK_ALERT_TOPIC_ARN")

    if topic_arn and result.decision == "BLOCK":
        sns.publish(
            TopicArn=topic_arn,
            Subject="Terraform change blocked",
            Message=json.dumps(payload, indent=2),
        )

    return payload


# Built by Imran Haider

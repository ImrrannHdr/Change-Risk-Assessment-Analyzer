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
    analysis_id = event.get("analysis_id", context.aws_request_id)

    response = s3.get_object(Bucket=bucket, Key=key)
    plan = json.loads(response["Body"].read())
    result = analyze_plan(plan, environment)
    payload = asdict(result)
    payload["analysis_id"] = analysis_id

    table_name = os.environ.get("ANALYSIS_RESULTS_TABLE")
    if table_name:
        table = dynamodb.Table(table_name)
        table.put_item(
            Item={
                "analysis_id": analysis_id,
                "risk_score": result.risk_score,
                "risk_level": result.risk_level,
                "decision": result.decision,
                "result": json.dumps(payload),
            }
        )

    topic_arn = os.environ.get("RISK_ALERT_TOPIC_ARN")
    if topic_arn and result.decision == "BLOCK":
        sns.publish(
            TopicArn=topic_arn,
            Subject="Terraform change blocked",
            Message=json.dumps(payload, indent=2),
        )

    return payload

# Build by Imran Haider

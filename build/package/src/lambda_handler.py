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
        "[SG-IMPACT] total=%d resolved=%d errors=%d incomplete=%d not_assessed=%d",
        summary["total_changes"], summary["resolved"],
        summary["context_errors"], summary["incomplete"],
        summary["not_assessed"],
    )
    for change in impacts:
        logger.info(
            "[SG-IMPACT] resource=%s classification=%s status=%s sg=%s",
            change["resource"], change["classification"],
            change["impact"]["status"], change["impact"]["security_group_id"],
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


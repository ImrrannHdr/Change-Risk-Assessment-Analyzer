resource "aws_lambda_function" "risk_analyzer" {
  function_name = var.function_name

  filename         = var.lambda_zip_path
  source_code_hash = filebase64sha256(var.lambda_zip_path)

  handler       = "src.lambda_handler.lambda_handler"
  runtime       = "python3.12"
  architectures = ["x86_64"]

  role = var.lambda_role_arn

  timeout     = 30
  memory_size = 256


  environment {
    variables = {
      ENVIRONMENT            = var.environment
      ANALYSIS_RESULTS_TABLE = var.analysis_results_table_name
      RISK_ALERT_TOPIC_ARN   = var.risk_alert_topic_arn
      ENABLE_CONTEXT_ANALYSIS = "true"
      ENABLE_ROUTE_CONTEXT_ANALYSIS = "true"
    }
  }

  tags = var.tags
}

# Build by Imran Haider
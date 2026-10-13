resource "aws_lambda_function" "risk_analyzer" {
  function_name = "change-risk-assessment-analyzer"

  filename = "${path.module}/../build/lambda.zip"

  source_code_hash = filebase64sha256(
    "${path.module}/../build/lambda.zip"
  )

  handler       = "src.lambda_handler.lambda_handler"
  runtime       = "python3.12"
  architectures = ["x86_64"]

  role = aws_iam_role.lambda_execution_role.arn

  timeout     = 30
  memory_size = 256

  environment {
    variables = {
      ENVIRONMENT = "dev"
    }
  }

  tags = {
    Project   = "Change-Risk-Assessment-Analyzer"
    ManagedBy = "Terraform"
  }
}
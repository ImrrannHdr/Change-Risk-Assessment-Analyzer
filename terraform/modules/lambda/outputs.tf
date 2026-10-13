output "function_name" {
  value = aws_lambda_function.risk_analyzer.function_name
}

output "function_arn" {
  value = aws_lambda_function.risk_analyzer.arn
}
/*
output "role_name" {
  description = "Lambda execution role name"
  value       = aws_iam_role.lambda_execution.name
}

output "role_arn" {
  description = "Lambda execution role ARN"
  value       = aws_iam_role.lambda_execution.arn
}
*/


# Build by Imran Haider

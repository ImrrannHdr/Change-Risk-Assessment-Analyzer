output "table_name" {
  description = "DynamoDB analysis results table name"
  value       = aws_dynamodb_table.analysis_results.name
}

output "table_arn" {
  description = "DynamoDB analysis results table ARN"
  value       = aws_dynamodb_table.analysis_results.arn
}






# Build by Imran Haider
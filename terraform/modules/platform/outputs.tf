output "plan_bucket" {
  value = aws_s3_bucket.plans.bucket
}

output "results_table" {
  value = aws_dynamodb_table.results.name
}

output "state_machine_arn" {
  value = aws_sfn_state_machine.analysis.arn
}

output "alert_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

# Build by Imran Haider

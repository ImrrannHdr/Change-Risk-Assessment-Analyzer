output "topic_arn" {
  description = "ARN of the SNS risk-alert topic"
  value       = aws_sns_topic.risk_alerts.arn
}

output "topic_name" {
  description = "Name of the SNS risk-alert topic"
  value       = aws_sns_topic.risk_alerts.name
}

# Build by Imran Haider

output "event_rule_name" {
  value = aws_cloudwatch_event_rule.plan_uploaded.name
}

output "event_rule_arn" {
  value = aws_cloudwatch_event_rule.plan_uploaded.arn
}



# Build by Imran Haider
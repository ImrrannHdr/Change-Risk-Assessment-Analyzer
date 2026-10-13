output "plan_bucket_name" {
  value = module.plan_storage.bucket_name
}

output "plan_bucket_arn" {
  value = module.plan_storage.bucket_arn
}

output "analysis_results_table_name" {
  value = module.analysis_results.table_name
}

output "analysis_results_table_arn" {
  value = module.analysis_results.table_arn
}

output "risk_alert_topic_arn" {
  value = module.notifications.topic_arn
}

output "risk_alert_topic_name" {
  value = module.notifications.topic_name
}

output "lambda_execution_role_name" {
  value = module.lambda_role.role_name
}

output "lambda_execution_role_arn" {
  value = module.lambda_role.role_arn
}
output "risk_analyzer_function_name" {
  value = module.lambda.function_name
}

output "risk_analyzer_function_arn" {
  value = module.lambda.function_arn
}

output "risk_state_machine_arn" {
  description = "ARN of the risk analysis workflow"
  value       = module.step_functions.state_machine_arn
}

output "eventbridge_rule_name" {
  value = module.eventbridge.event_rule_name
}

output "eventbridge_rule_arn" {
  value = module.eventbridge.event_rule_arn
}
output "github_actions_role_arn" {
  value = module.github_oidc.role_arn
}




# Build by Imran Haider

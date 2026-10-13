output "state_machine_arn" {
  description = "Risk analysis Step Functions ARN"
  value       = aws_sfn_state_machine.risk_analysis.arn
}
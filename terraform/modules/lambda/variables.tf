variable "function_name" {
  description = "Name of the Lambda function"
  type        = string
}

variable "lambda_zip_path" {
  description = "Path to the Lambda deployment ZIP"
  type        = string
}

variable "lambda_role_arn" {
  description = "IAM execution role ARN used by Lambda"
  type        = string
}

variable "analysis_results_table_name" {
  description = "DynamoDB table name used to store analysis results"
  type        = string
}

variable "risk_alert_topic_arn" {
  description = "SNS topic ARN used for risk notifications"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "dev"
}

variable "tags" {
  description = "Tags applied to the Lambda function"
  type        = map(string)
  default     = {}
}

# Build by Imran Haider
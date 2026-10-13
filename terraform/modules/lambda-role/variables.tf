variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

variable "plan_bucket_arn" {
  description = "ARN of the S3 bucket containing Terraform plans"
  type        = string
}

variable "analysis_results_table_arn" {
  description = "ARN of the DynamoDB analysis results table"
  type        = string
}

variable "risk_alert_topic_arn" {
  description = "ARN of the SNS topic used for risk notifications"
  type        = string
}

variable "tags" {
  description = "Common resource tags"
  type        = map(string)
  default     = {}
}

# Build by Imran Haider

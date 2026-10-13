variable "project_name" {
  description = "Project name"
  type        = string
}

variable "lambda_function_arn" {
  description = "ARN of the risk analyzer Lambda"
  type        = string
}

variable "tags" {
  description = "AWS resource tags"
  type        = map(string)
  default     = {}
}
variable "project_name" {
  type    = string
  default = "aws-iac-risk-engine"
}

variable "lambda_zip_path" {
  type        = string
  description = "Path to deployment zip containing the src package and dependencies."
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "lambda_function_arn" {
  type        = string
  description = "ARN of the Lambda function to be invoked by the Step Function."
}
# Build by Imran Haider

variable "project_name" {
  description = "Change Risk Analyzer - Imran Haider"
  type        = string
}

variable "tags" {
  description = "Common resource tags"
  type        = map(string)
  default     = {}
}

variable "state_machine_arn" {
  type        = string
  description = "ARN of the Step Function state machine to be invoked by the S3 event."
}

variable "plan_bucket_name" {
  type        = string
  description = "Name of the S3 bucket containing Terraform plans."
}
variable "environment"{
  type        = string
  description = "Environment name (e.g., dev, prod)."
  default = "dev"
}
variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

variable "email_endpoint" {
  description = "Email address used for risk notifications"
  type        = string
  default     = null
}

variable "tags" {
  description = "Common resource tags"
  type        = map(string)
  default     = {}
}

# Build by Imran Haider

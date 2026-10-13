variable "project_name" {
  type = string
}

variable "github_repository" {
  description = "GitHub repository in owner/repo format"
  type        = string
}

variable "github_oidc_provider_arn" {
  type = string
}

variable "plan_bucket_arn" {
  type = string
}

variable "terraform_state_bucket_arn" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}

# Build by Imran Haider
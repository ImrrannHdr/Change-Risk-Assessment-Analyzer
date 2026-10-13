output "bucket_name" {
  description = "Terraform plan storage bucket name"
  value       = aws_s3_bucket.plans.id
}

output "bucket_arn" {
  description = "Terraform plan storage bucket ARN"
  value       = aws_s3_bucket.plans.arn
}

# Build by Imran Haider

resource "aws_s3_bucket" "plans" {
  bucket = "${var.project_name}-plans-output"

  tags = merge(
    var.tags,
    {
      Name = "${var.project_name}-plans-output"
    }
  )
}

resource "aws_s3_bucket_versioning" "plans" {
  bucket = aws_s3_bucket.plans.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "plans" {
  bucket = aws_s3_bucket.plans.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "plans" {
  bucket = aws_s3_bucket.plans.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

}

resource "aws_s3_bucket_notification" "eventbridge" {
  bucket      = aws_s3_bucket.plans.id
  eventbridge = true
}


# Build by Imran Haider
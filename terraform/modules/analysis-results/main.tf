resource "aws_dynamodb_table" "analysis_results" {
  name         = "${var.project_name}-analysis-results"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "analysis_id"

  attribute {
    name = "analysis_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.project_name}-analysis-results"
    }
  )
}

# Build by Imran Haider

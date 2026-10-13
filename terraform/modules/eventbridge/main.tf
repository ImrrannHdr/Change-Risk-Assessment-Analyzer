data "aws_iam_policy_document" "eventbridge_assume_role" {
  statement {
    effect = "Allow"

    actions = [
      "sts:AssumeRole"
    ]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eventbridge" {
  name = "${var.project_name}-eventbridge-role"

  assume_role_policy = data.aws_iam_policy_document.eventbridge_assume_role.json

  tags = var.tags
}

data "aws_iam_policy_document" "eventbridge_permissions" {
  statement {
    effect = "Allow"

    actions = [
      "states:StartExecution"
    ]

    resources = [
      var.state_machine_arn
    ]
  }
}

resource "aws_iam_role_policy" "eventbridge" {
  name   = "${var.project_name}-eventbridge-policy"
  role   = aws_iam_role.eventbridge.id
  policy = data.aws_iam_policy_document.eventbridge_permissions.json
}

resource "aws_cloudwatch_event_rule" "plan_uploaded" {
  name        = "${var.project_name}-plan-uploaded"
  description = "Starts risk analysis when a Terraform plan JSON file is uploaded"

  event_pattern = jsonencode({
    source = [
      "aws.s3"
    ]

    detail-type = [
      "Object Created"
    ]

    detail = {
      bucket = {
        name = [
          var.plan_bucket_name
        ]
      }

      object = {
        key = [
          {
            suffix = ".json"
          }
        ]
      }
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "step_functions" {
  rule = aws_cloudwatch_event_rule.plan_uploaded.name
  arn  = var.state_machine_arn

  role_arn = aws_iam_role.eventbridge.arn

  input_transformer {
    input_paths = {
      bucket = "$.detail.bucket.name"
      key    = "$.detail.object.key"
    }

    input_template = <<EOF
{
  "bucket": <bucket>,
  "key": <key>,
  "environment": "${var.environment}"
}
EOF
  }
}

# Build by Imran Haider
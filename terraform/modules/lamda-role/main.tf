data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect = "Allow"

    actions = [
      "sts:AssumeRole"
    ]

    principals {
      type = "Service"

      identifiers = [
        "lambda.amazonaws.com"
      ]
    }
  }
}

resource "aws_iam_role" "lambda_execution" {
  name = "${var.project_name}-lambda-execution-role"

  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = merge(
    var.tags,
    {
      Name = "${var.project_name}-lambda-execution-role"
    }
  )
}

data "aws_iam_policy_document" "lambda_permissions" {

  statement {
    sid    = "ReadTerraformPlans"
    effect = "Allow"

    actions = [
      "s3:GetObject"
    ]

    resources = [
      "${var.plan_bucket_arn}/*"
    ]
  }

  statement {
    sid    = "WriteAnalysisResults"
    effect = "Allow"

    actions = [
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:GetItem"
    ]

    resources = [
      var.analysis_results_table_arn
    ]
  }

  statement {
    sid    = "PublishRiskAlerts"
    effect = "Allow"

    actions = [
      "sns:Publish"
    ]

    resources = [
      var.risk_alert_topic_arn
    ]
  }

  statement {
    sid    = "CloudWatchLogging"
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]

    resources = [
      "arn:aws:logs:*:*:*"
    ]
  }
}

resource "aws_iam_role_policy" "lambda_permissions" {
  name = "${var.project_name}-lambda-permissions"
  role = aws_iam_role.lambda_execution.id

  policy = data.aws_iam_policy_document.lambda_permissions.json
}

# Build by Imran Haider

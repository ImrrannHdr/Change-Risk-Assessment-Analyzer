
# ---------------------------------------
# Lambda Trust Policy
# ---------------------------------------

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect = "Allow"

    actions = [
      "sts:AssumeRole"
    ]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}


# ---------------------------------------
# Lambda Execution Role
# ---------------------------------------

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


# ---------------------------------------
# AWS Lambda Basic Logging
# ---------------------------------------

resource "aws_iam_role_policy_attachment" "basic_logging" {
  role       = aws_iam_role.lambda_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}


# ---------------------------------------
# Lambda Permissions Policy
# ---------------------------------------

data "aws_iam_policy_document" "lambda_permissions" {

  # Read Terraform plan files from S3
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

  # Store risk analysis results in DynamoDB
  statement {
    sid    = "WriteAnalysisResults"
    effect = "Allow"

    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:UpdateItem"
    ]

    resources = [
      var.analysis_results_table_arn
    ]
  }

  # Discover AWS resources attached to security groups
  statement {
    sid    = "DescribeNetworkInterfaces"
    effect = "Allow"

    actions = [
      "ec2:DescribeNetworkInterfaces"
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "ec2:Region"
      values   = ["ap-southeast-2"]
    }
  }

  # Publish risk notifications through SNS
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
}


# ---------------------------------------
# Attach Inline Permissions to Lambda Role
# ---------------------------------------

resource "aws_iam_role_policy" "lambda_permissions" {
  name   = "${var.project_name}-lambda-permissions"
  role   = aws_iam_role.lambda_execution.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}

# Build by Imran Haider

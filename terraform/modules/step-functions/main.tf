data "aws_iam_policy_document" "assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  name               = "${var.project_name}-step-functions-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = var.tags
}

data "aws_iam_policy_document" "permissions" {
  statement {
    effect = "Allow"

    actions = [
      "lambda:InvokeFunction"
    ]

    resources = [
      var.lambda_function_arn
    ]
  }
}

resource "aws_iam_role_policy" "this" {
  name   = "${var.project_name}-step-functions-policy"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.permissions.json
}

resource "aws_sfn_state_machine" "risk_analysis" {
  name     = "${var.project_name}-risk-analysis"
  role_arn = aws_iam_role.this.arn
  type     = "STANDARD"

  definition = jsonencode({
    Comment = "Terraform risk analysis workflow"

    StartAt = "AnalyzePlan"

    States = {
      AnalyzePlan = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"

        Parameters = {
          FunctionName = var.lambda_function_arn

          Payload = {
            "bucket.$"      = "$.bucket"
            "key.$"         = "$.key"
            "environment.$" = "$.environment"
          }
        }

        OutputPath = "$.Payload"



        Next = "EvaluateDecision"

        Retry = [
          {
            ErrorEquals = [
              "Lambda.ServiceException",
              "Lambda.AWSLambdaException",
              "Lambda.SdkClientException"
            ]

            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2
          }
        ]

        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next        = "AnalysisFailed"
          }
        ]
      }

      EvaluateDecision = {
        Type = "Choice"

        Choices = [
          {
            Variable     = "$.decision"
            StringEquals = "ALLOW"
            Next         = "Allowed"
          },
          {
            Variable     = "$.decision"
            StringEquals = "APPROVAL_REQUIRED"
            Next         = "ApprovalRequired"
          },
          {
            Variable     = "$.decision"
            StringEquals = "BLOCK"
            Next         = "Blocked"
          }
        ]

        Default = "UnknownDecision"
      }

      Allowed = {
        Type = "Succeed"
      }

      ApprovalRequired = {
        Type = "Succeed"
      }

      Blocked = {
        Type = "Succeed"
      }

      AnalysisFailed = {
        Type  = "Fail"
        Error = "RiskAnalysisFailed"
        Cause = "The Lambda risk analyzer failed."
      }

      UnknownDecision = {
        Type  = "Fail"
        Error = "UnknownDecision"
        Cause = "Unexpected risk engine decision."
      }
    }
  })

  tags = var.tags
  depends_on = [
    aws_iam_role_policy.this
  ]
}

# Build by Imran Haider

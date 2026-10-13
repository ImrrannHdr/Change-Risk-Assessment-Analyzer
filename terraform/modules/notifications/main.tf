resource "aws_sns_topic" "risk_alerts" {
  name = "${var.project_name}-risk-alerts"

  tags = merge(
    var.tags,
    {
      Name = "${var.project_name}-risk-alerts"
    }
  )
}

resource "aws_sns_topic_subscription" "email" {
  count = var.email_endpoint != null ? 1 : 0

  topic_arn = aws_sns_topic.risk_alerts.arn
  protocol  = "email"
  endpoint  = var.email_endpoint
}

# Build by Imran Haider

variable "alert_email" {
  description = "Email address to subscribe to security alert notifications"
  type        = string
}

resource "aws_sns_topic" "alerts" {
  name = "cloudguard-alerts"

  tags = {
    Module = "sns"
  }
}

# Email subscription requires manual confirmation (link sent to the inbox) —
# this is expected and noted in the evidence checklist.
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Topic policy: only this account's Lambdas (via IAM role policy, not topic
# policy) are expected to publish. Topic policy here just allows the
# account itself, keeping the topic from being publicly publishable.
resource "aws_sns_topic_policy" "default" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAccountPublish"
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action    = "SNS:Publish"
        Resource  = aws_sns_topic.alerts.arn
        Condition = {
          StringEquals = {
            "AWS:SourceOwner" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

data "aws_caller_identity" "current" {}

output "topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "topic_name" {
  value = aws_sns_topic.alerts.name
}

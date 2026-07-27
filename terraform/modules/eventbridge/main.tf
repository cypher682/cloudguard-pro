# EventBridge module
#
# Lambda target ARNs are passed in as variables and default to null.
# Until Pulumi deploys the Lambda layer (Step 10), `terraform plan`
# will show rules created WITHOUT targets attached (targets are
# conditionally created only when an ARN is supplied). This lets the
# module validate and plan cleanly today, and targets get attached in
# a second `terraform apply` once Lambda ARNs exist — no rewrite needed.

variable "event_ingestor_lambda_arn" {
  type    = string
  default = null
}

variable "sg_remediator_lambda_arn" {
  type    = string
  default = null
}

variable "s3_remediator_lambda_arn" {
  type    = string
  default = null
}

variable "iam_remediator_lambda_arn" {
  type    = string
  default = null
}

variable "cis_scanner_lambda_arn" {
  type    = string
  default = null
}

variable "security_hub_sync_lambda_arn" {
  type    = string
  default = null
}

variable "cis_scan_schedule_expression" {
  description = "EventBridge schedule expression for the CIS scanner (default: every 6 hours)"
  type        = string
  default     = "rate(6 hours)"
}

variable "security_hub_sync_schedule_expression" {
  description = "EventBridge schedule expression for the daily Security Hub sync"
  type        = string
  default     = "rate(1 day)"
}

# --- Custom event bus ---
# A custom bus (rather than the default bus) keeps cloudguard's rules
# isolated from any other EventBridge usage in the account.

resource "aws_cloudwatch_event_bus" "cloudguard" {
  name = "cloudguard-pro-bus"

  tags = {
    Module = "eventbridge"
  }
}

# CloudTrail delivers management events to the DEFAULT bus only, so a
# forwarding rule on the default bus relays relevant events to the
# custom bus. This keeps the custom bus as the single source of truth
# for cloudguard-specific routing while not touching anything else
# that might use the default bus.

resource "aws_cloudwatch_event_rule" "forward_to_custom_bus" {
  name           = "cloudguard-forward-cloudtrail-events"
  description    = "Forwards relevant CloudTrail events from the default bus to the cloudguard custom bus"
  event_bus_name = "default"

  event_pattern = jsonencode({
    source      = ["aws.ec2", "aws.s3", "aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
  })

  tags = {
    Module = "eventbridge"
  }
}

resource "aws_cloudwatch_event_target" "forward_target" {
  rule           = aws_cloudwatch_event_rule.forward_to_custom_bus.name
  event_bus_name = "default"
  arn            = aws_cloudwatch_event_bus.cloudguard.arn
  target_id      = "forward-to-cloudguard-bus"
  role_arn       = aws_iam_role.eventbridge_forward_role.arn
}

resource "aws_iam_role" "eventbridge_forward_role" {
  name = "cloudguard-eventbridge-forward-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Module = "eventbridge"
  }
}

resource "aws_iam_role_policy" "eventbridge_forward_policy" {
  name = "cloudguard-eventbridge-forward-policy"
  role = aws_iam_role.eventbridge_forward_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "events:PutEvents"
      Resource = aws_cloudwatch_event_bus.cloudguard.arn
    }]
  })
}

# --- event-ingestor: catches everything on the custom bus ---
# Every CloudTrail event that lands on the custom bus is ingested first,
# enriched, and stored. Remediators below trigger independently/in
# parallel on more specific patterns.

resource "aws_cloudwatch_event_rule" "all_events_to_ingestor" {
  name           = "cloudguard-all-events-to-ingestor"
  description    = "Routes every event on the custom bus to event-ingestor for storage"
  event_bus_name = aws_cloudwatch_event_bus.cloudguard.name

  event_pattern = jsonencode({
    source = ["aws.ec2", "aws.s3", "aws.iam"]
  })

  tags = {
    Module = "eventbridge"
  }
}

resource "aws_cloudwatch_event_target" "ingestor_target" {
  count          = var.event_ingestor_lambda_arn != null ? 1 : 0
  rule           = aws_cloudwatch_event_rule.all_events_to_ingestor.name
  event_bus_name = aws_cloudwatch_event_bus.cloudguard.name
  arn            = var.event_ingestor_lambda_arn
  target_id      = "event-ingestor"
}

# --- sg-remediator: EC2 security group modification events ---

resource "aws_cloudwatch_event_rule" "sg_changes" {
  name           = "cloudguard-sg-changes"
  description    = "Security group ingress rule modifications"
  event_bus_name = aws_cloudwatch_event_bus.cloudguard.name

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AuthorizeSecurityGroupIngress",
        "ModifySecurityGroupRules"
      ]
    }
  })

  tags = {
    Module = "eventbridge"
  }
}

resource "aws_cloudwatch_event_target" "sg_remediator_target" {
  count          = var.sg_remediator_lambda_arn != null ? 1 : 0
  rule           = aws_cloudwatch_event_rule.sg_changes.name
  event_bus_name = aws_cloudwatch_event_bus.cloudguard.name
  arn            = var.sg_remediator_lambda_arn
  target_id      = "sg-remediator"
}

# --- s3-remediator: S3 bucket public access / policy changes ---

resource "aws_cloudwatch_event_rule" "s3_policy_changes" {
  name           = "cloudguard-s3-policy-changes"
  description    = "S3 bucket public access or policy modifications"
  event_bus_name = aws_cloudwatch_event_bus.cloudguard.name

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "PutBucketPolicy",
        "PutBucketAcl",
        "PutPublicAccessBlock",
        "DeletePublicAccessBlock"
      ]
    }
  })

  tags = {
    Module = "eventbridge"
  }
}

resource "aws_cloudwatch_event_target" "s3_remediator_target" {
  count          = var.s3_remediator_lambda_arn != null ? 1 : 0
  rule           = aws_cloudwatch_event_rule.s3_policy_changes.name
  event_bus_name = aws_cloudwatch_event_bus.cloudguard.name
  arn            = var.s3_remediator_lambda_arn
  target_id      = "s3-remediator"
}

# --- iam-remediator: IAM console access / login profile changes ---

resource "aws_cloudwatch_event_rule" "iam_changes" {
  name           = "cloudguard-iam-changes"
  description    = "IAM user login profile and console access changes"
  event_bus_name = aws_cloudwatch_event_bus.cloudguard.name

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateLoginProfile",
        "UpdateLoginProfile",
        "CreateUser"
      ]
    }
  })

  tags = {
    Module = "eventbridge"
  }
}

resource "aws_cloudwatch_event_target" "iam_remediator_target" {
  count          = var.iam_remediator_lambda_arn != null ? 1 : 0
  rule           = aws_cloudwatch_event_rule.iam_changes.name
  event_bus_name = aws_cloudwatch_event_bus.cloudguard.name
  arn            = var.iam_remediator_lambda_arn
  target_id      = "iam-remediator"
}

# --- cis-scanner: scheduled, every 6 hours ---
# Scheduled rules live on the DEFAULT bus (EventBridge Scheduler/Rules
# scheduled expressions are bus-scoped; using default here is simplest
# and standard practice for scheduled invocations).

resource "aws_cloudwatch_event_rule" "cis_scan_schedule" {
  name                = "cloudguard-cis-scan-schedule"
  description         = "Triggers cis-scanner on a recurring schedule"
  schedule_expression = var.cis_scan_schedule_expression

  tags = {
    Module = "eventbridge"
  }
}

resource "aws_cloudwatch_event_target" "cis_scanner_target" {
  count = var.cis_scanner_lambda_arn != null ? 1 : 0
  rule  = aws_cloudwatch_event_rule.cis_scan_schedule.name
  arn   = var.cis_scanner_lambda_arn
}

# --- security-hub-sync: scheduled, daily ---

resource "aws_cloudwatch_event_rule" "security_hub_sync_schedule" {
  name                = "cloudguard-security-hub-sync-schedule"
  description         = "Triggers security-hub-sync daily to pull aggregated findings"
  schedule_expression = var.security_hub_sync_schedule_expression

  tags = {
    Module = "eventbridge"
  }
}

resource "aws_cloudwatch_event_target" "security_hub_sync_target" {
  count = var.security_hub_sync_lambda_arn != null ? 1 : 0
  rule  = aws_cloudwatch_event_rule.security_hub_sync_schedule.name
  arn   = var.security_hub_sync_lambda_arn
}

# --- Outputs ---
# Lambda-permission resources (allowing EventBridge to invoke each
# function) are created in Pulumi alongside the Lambda itself, since
# Pulumi owns the Lambda resource and the permission must reference
# these rule ARNs. Outputs below expose what Pulumi needs.

output "bus_name" {
  value = aws_cloudwatch_event_bus.cloudguard.name
}

output "bus_arn" {
  value = aws_cloudwatch_event_bus.cloudguard.arn
}

output "all_events_rule_arn" {
  value = aws_cloudwatch_event_rule.all_events_to_ingestor.arn
}

output "sg_changes_rule_arn" {
  value = aws_cloudwatch_event_rule.sg_changes.arn
}

output "s3_policy_changes_rule_arn" {
  value = aws_cloudwatch_event_rule.s3_policy_changes.arn
}

output "iam_changes_rule_arn" {
  value = aws_cloudwatch_event_rule.iam_changes.arn
}

output "cis_scan_schedule_rule_arn" {
  value = aws_cloudwatch_event_rule.cis_scan_schedule.arn
}

output "security_hub_sync_schedule_rule_arn" {
  value = aws_cloudwatch_event_rule.security_hub_sync_schedule.arn
}

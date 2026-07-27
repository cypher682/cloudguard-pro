# AWS Config module
#
# Provides continuous compliance evaluation as a SECOND detection layer
# alongside the CloudTrail/EventBridge real-time path. Config catches
# drift even when no API call triggered an event (e.g. a resource
# created before cloudguard-pro existed, or state changes Config
# discovers on its periodic re-evaluation).
#
# Only AWS-managed rules are used here — no custom Lambda-backed Config
# rules, since cis-scanner already covers checks with no managed-rule
# equivalent. This avoids duplicating logic across two layers.

variable "config_bucket_name" {
  description = "S3 bucket name for AWS Config delivery channel"
  type        = string
  default     = "" # generated if not supplied
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  bucket_name = var.config_bucket_name != "" ? var.config_bucket_name : "cloudguard-config-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
}

resource "aws_s3_bucket" "config" {
  bucket = local.bucket_name

  tags = {
    Module = "config-rules"
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket = aws_s3_bucket.config.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSConfigBucketPermissionsCheck"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.config.arn
      },
      {
        Sid       = "AWSConfigBucketDelivery"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.config.arn}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

resource "aws_iam_role" "config" {
  name = "cloudguard-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Module = "config-rules"
  }
}

resource "aws_iam_role_policy_attachment" "config_managed" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "cloudguard" {
  name     = "cloudguard-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "cloudguard" {
  name           = "cloudguard-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config.bucket

  depends_on = [aws_config_configuration_recorder.cloudguard]
}

resource "aws_config_configuration_recorder_status" "cloudguard" {
  name       = aws_config_configuration_recorder.cloudguard.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.cloudguard]
}

# --- Managed Config Rules ---
# Each maps to a CIS AWS Foundations Benchmark check (see docs/cis-checks.md).

resource "aws_config_config_rule" "s3_public_access_blocked" {
  name = "cloudguard-s3-bucket-public-access-blocked"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.cloudguard]
  tags       = { Module = "config-rules", CisCheck = "2.1.1" }
}

resource "aws_config_config_rule" "ebs_encrypted" {
  name = "cloudguard-ebs-encrypted-volumes"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder.cloudguard]
  tags       = { Module = "config-rules", CisCheck = "2.2.1" }
}

resource "aws_config_config_rule" "root_mfa_enabled" {
  name = "cloudguard-root-account-mfa-enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.cloudguard]
  tags       = { Module = "config-rules", CisCheck = "1.5" }
}

resource "aws_config_config_rule" "iam_user_mfa_enabled" {
  name = "cloudguard-iam-user-mfa-enabled"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.cloudguard]
  tags       = { Module = "config-rules", CisCheck = "1.10" }
}

resource "aws_config_config_rule" "restricted_ssh" {
  name = "cloudguard-restricted-ssh"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder.cloudguard]
  tags       = { Module = "config-rules", CisCheck = "4.1" }
}

resource "aws_config_config_rule" "cloudtrail_enabled" {
  name = "cloudguard-cloudtrail-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.cloudguard]
  tags       = { Module = "config-rules", CisCheck = "3.1" }
}

output "config_bucket_name" {
  value = aws_s3_bucket.config.bucket
}

output "recorder_name" {
  value = aws_config_configuration_recorder.cloudguard.name
}

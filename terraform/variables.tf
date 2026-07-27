variable "aws_region" {
  description = "AWS region for all cloudguard-pro resources"
  type        = string
  default     = "us-east-1"
}

variable "findings_table_name" {
  description = "DynamoDB table name for storing security findings"
  type        = string
  default     = "cloudguard-findings"
}

variable "alert_email" {
  description = "Email address for SNS finding notifications"
  type        = string
  # No default — must be supplied via terraform.tfvars at sprint time,
  # never committed (see terraform.tfvars.example)
}

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

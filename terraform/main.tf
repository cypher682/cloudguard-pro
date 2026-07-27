terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Independent state backend for cloudguard-pro — not shared with infra-core (F3).
  # Bucket and lock table are provisioned once via terraform/modules/state-backend
  # using a local-state bootstrap run, then this block is activated.
  backend "s3" {
    bucket         = "cloudguard-pro-tfstate-758620460011" # see .env.example TF_STATE_BUCKET
    key            = "cloudguard-pro/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "cloudguard-pro-tfstate-lock" # see .env.example TF_STATE_LOCK_TABLE
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "cloudguard-pro"
      ManagedBy = "terraform"
      Sprint    = "true"
    }
  }
}

# --- Module wiring (modules implemented in Step 2) ---

module "dynamodb" {
  source = "./modules/dynamodb"

  table_name = var.findings_table_name
}

module "sns" {
  source = "./modules/sns"

  alert_email = var.alert_email
}

module "eventbridge" {
  source = "./modules/eventbridge"

  event_ingestor_lambda_arn    = var.event_ingestor_lambda_arn
  sg_remediator_lambda_arn     = var.sg_remediator_lambda_arn
  s3_remediator_lambda_arn     = var.s3_remediator_lambda_arn
  iam_remediator_lambda_arn    = var.iam_remediator_lambda_arn
  cis_scanner_lambda_arn       = var.cis_scanner_lambda_arn
  security_hub_sync_lambda_arn = var.security_hub_sync_lambda_arn
}

module "config_rules" {
  source = "./modules/config-rules"
}

module "security_hub" {
  source = "./modules/security-hub"
}

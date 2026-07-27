# State backend bootstrap
#
# This is NOT invoked as a module from terraform/main.tf — it's a
# standalone, self-contained Terraform config you run ONCE, locally,
# with local state, to create the S3 bucket + DynamoDB lock table that
# terraform/main.tf's `backend "s3"` block then points to.
#
# Independent from F3 (infra-core) — cloudguard-pro owns its own state
# bucket and lock table, per the locked plan (no shared backend).
#
# --- Usage (run only once, at sprint time) ---
#   cd terraform/modules/state-backend
#   terraform init
#   terraform apply
#   # copy the bucket_name and lock_table_name outputs into
#   # terraform/main.tf's backend block, then:
#   cd ../../
#   terraform init   # migrates to the new S3 backend

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  # Intentionally no backend block here — this config's own state
  # stays local (or you can move it to S3 manually after, it's
  # small/disposable/recreatable).
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "bucket_name" {
  description = "Globally-unique S3 bucket name for Terraform state"
  type        = string
}

variable "lock_table_name" {
  description = "DynamoDB table name for Terraform state locking"
  type        = string
  default     = "cloudguard-pro-tfstate-lock"
}

resource "aws_s3_bucket" "tfstate" {
  bucket = var.bucket_name

  # Prevents accidental destruction of state via `terraform destroy`
  # on this bootstrap config — state loss is the one thing we can't
  # easily recover from.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket                  = aws_s3_bucket.tfstate.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_dynamodb_table" "tfstate_lock" {
  name         = var.lock_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  lifecycle {
    prevent_destroy = true
  }
}

output "bucket_name" {
  value = aws_s3_bucket.tfstate.bucket
}

output "lock_table_name" {
  value = aws_dynamodb_table.tfstate_lock.name
}

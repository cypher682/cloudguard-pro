variable "table_name" {
  description = "Name of the DynamoDB findings table"
  type        = string
}

# Schema matches lambdas/shared/models.py::Finding exactly.
# Partition key + sort key + two GSIs (severity, service) for query patterns
# used by finding-notifier, cis-scanner, and any future dashboard reads.

resource "aws_dynamodb_table" "findings" {
  name         = var.table_name
  billing_mode = "PAY_PER_REQUEST" # sprint-friendly — no provisioned capacity to pay for idle

  hash_key  = "finding_id"
  range_key = "created_at"

  attribute {
    name = "finding_id"
    type = "S"
  }

  attribute {
    name = "created_at"
    type = "S"
  }

  attribute {
    name = "severity"
    type = "S"
  }

  attribute {
    name = "service"
    type = "S"
  }

  global_secondary_index {
    name            = "severity-index"
    hash_key        = "severity"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "service-index"
    hash_key        = "service"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # Streams enabled -> finding-notifier Lambda triggers on INSERT (new findings only)
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Module = "dynamodb"
  }
}

output "table_name" {
  value = aws_dynamodb_table.findings.name
}

output "table_arn" {
  value = aws_dynamodb_table.findings.arn
}

output "stream_arn" {
  description = "DynamoDB Streams ARN, consumed by finding-notifier's event source mapping"
  value       = aws_dynamodb_table.findings.stream_arn
}

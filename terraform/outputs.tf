output "findings_table_name" {
  description = "Name of the DynamoDB findings table"
  value       = module.dynamodb.table_name
}

output "findings_table_arn" {
  description = "ARN of the DynamoDB findings table"
  value       = module.dynamodb.table_arn
}

output "findings_table_stream_arn" {
  description = "DynamoDB Streams ARN, consumed by the finding-notifier Lambda"
  value       = module.dynamodb.stream_arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for security alerts"
  value       = module.sns.topic_arn
}

output "eventbridge_bus_name" {
  description = "Name of the custom EventBridge event bus"
  value       = module.eventbridge.bus_name
}

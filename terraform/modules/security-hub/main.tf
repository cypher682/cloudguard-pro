# Security Hub module
#
# Enables Security Hub and subscribes to the CIS AWS Foundations
# Benchmark standard, so findings from GuardDuty/Inspector/Macie/Config
# are aggregated centrally. security-hub-sync Lambda pulls from this
# aggregated view daily into the cloudguard DynamoDB findings table.

data "aws_region" "current" {}

resource "aws_securityhub_account" "cloudguard" {
  enable_default_standards = false # we subscribe explicitly below, avoid unwanted extras
}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/cis-aws-foundations-benchmark/v/1.4.0"

  depends_on = [aws_securityhub_account.cloudguard]
}

resource "aws_securityhub_standards_subscription" "aws_foundational" {
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.cloudguard]
}

output "security_hub_account_id" {
  value = aws_securityhub_account.cloudguard.id
}

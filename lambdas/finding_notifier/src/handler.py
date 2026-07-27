"""
finding-notifier Lambda

Triggered by DynamoDB Streams on the findings table (INSERT events only).
For each new finding, publishes a formatted SNS notification to the
cloudguard-alerts topic.

Only processes INSERT records — UPDATE events (e.g. status changes from
remediators) do not trigger a second notification.

Notification format is human-readable: subject line includes severity
and finding type, body includes all key context for action.
"""

from __future__ import annotations

import os
from typing import Any

import boto3

from lambdas.shared.logger import get_logger
from lambdas.shared.models import Finding, FindingStatus

logger = get_logger("finding-notifier")


def _deserialize_dynamo_item(record: dict) -> dict:
    """
    Convert a DynamoDB Streams NewImage (type-annotated dict) to a plain
    Python dict. Only handles S (String) and N (Number) types since the
    findings table only uses those.
    """
    result = {}
    for key, value in record.items():
        if "S" in value:
            result[key] = value["S"]
        elif "N" in value:
            result[key] = value["N"]
        elif "BOOL" in value:
            result[key] = value["BOOL"]
        elif "NULL" in value:
            result[key] = None
        elif "M" in value:
            result[key] = _deserialize_dynamo_item(value["M"])
        else:
            result[key] = str(value)
    return result


def _format_subject(finding: Finding) -> str:
    return f"[{finding.severity.value}] CloudGuard: {finding.finding_type} on {finding.service.upper()}"


def _format_message(finding: Finding) -> str:
    lines = [
        f"CloudGuard Security Finding",
        f"{'=' * 40}",
        f"Severity:     {finding.severity.value}",
        f"Status:       {finding.status.value}",
        f"Service:      {finding.service.upper()}",
        f"Finding Type: {finding.finding_type}",
        f"Resource:     {finding.resource_id}",
        f"Region:       {finding.region}",
        f"Account:      {finding.account_id}",
        f"Detected At:  {finding.created_at}",
        f"Finding ID:   {finding.finding_id}",
        f"",
        f"Description:",
        f"  {finding.description}",
    ]

    if finding.status == FindingStatus.REMEDIATED:
        lines += [
            f"",
            f"Auto-Remediation:",
            f"  Action:  {finding.remediation_action}",
            f"  Applied: {finding.remediated_at}",
        ]

    if finding.cis_check_id:
        lines.append(f"")
        lines.append(f"CIS Check: {finding.cis_check_id}")

    lines += [
        f"",
        f"Review findings in DynamoDB table: {os.environ.get('FINDINGS_TABLE_NAME', 'cloudguard-findings')}",
    ]

    return "\n".join(lines)


def handler(event: dict[str, Any], context: Any) -> dict:
    sns_topic_arn = os.environ["SNS_TOPIC_ARN"]
    sns = boto3.client("sns", region_name=os.environ.get("AWS_REGION", "us-east-1"))

    records = event.get("Records", [])
    published = 0
    skipped = 0

    for record in records:
        # Only process INSERT events (new findings, not status updates)
        if record.get("eventName") != "INSERT":
            skipped += 1
            continue

        new_image = record.get("dynamodb", {}).get("NewImage")
        if not new_image:
            skipped += 1
            continue

        try:
            item = _deserialize_dynamo_item(new_image)
            finding = Finding.from_item(item)
        except Exception as exc:
            logger.error("Failed to deserialise finding from stream record", extra={
                "context": {"error": str(exc)}
            })
            skipped += 1
            continue

        subject = _format_subject(finding)
        message = _format_message(finding)

        try:
            sns.publish(
                TopicArn=sns_topic_arn,
                Subject=subject[:100],  # SNS subject max is 100 chars
                Message=message,
                MessageAttributes={
                    "severity": {
                        "DataType": "String",
                        "StringValue": finding.severity.value,
                    },
                    "service": {
                        "DataType": "String",
                        "StringValue": finding.service,
                    },
                    "status": {
                        "DataType": "String",
                        "StringValue": finding.status.value,
                    },
                },
            )
            published += 1
            logger.info("SNS notification published", extra={"context": {
                "finding_id": finding.finding_id,
                "severity": finding.severity.value,
                "subject": subject,
            }})
        except Exception as exc:
            logger.error("Failed to publish SNS notification", extra={"context": {
                "finding_id": finding.finding_id,
                "error": str(exc),
            }})

    logger.info("finding-notifier complete", extra={"context": {
        "total_records": len(records),
        "published": published,
        "skipped": skipped,
    }})

    return {"statusCode": 200, "published": published, "skipped": skipped}

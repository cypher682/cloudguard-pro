"""
event-ingestor Lambda

Triggered by EventBridge for every CloudTrail event on the cloudguard
custom bus (aws.ec2, aws.s3, aws.iam sources).

Responsibilities:
- Parse and normalise the raw EventBridge event
- Construct a Finding record
- Write to DynamoDB (which triggers finding-notifier via Streams)

This Lambda does NOT remediate — it only ingests and stores.
Remediator Lambdas are triggered independently by their own,
more-specific EventBridge rules in parallel.
"""

from __future__ import annotations

import os
from typing import Any

from lambdas.shared.dynamo_client import FindingsTable
from lambdas.shared.logger import get_logger
from lambdas.shared.models import Finding, FindingSource, FindingStatus, Severity

logger = get_logger("event-ingestor")

# Severity mapping by event category — remediators override status later
_SEVERITY_MAP: dict[str, Severity] = {
    # EC2
    "AuthorizeSecurityGroupIngress": Severity.HIGH,
    "ModifySecurityGroupRules": Severity.HIGH,
    # S3
    "PutBucketPolicy": Severity.HIGH,
    "PutBucketAcl": Severity.HIGH,
    "DeletePublicAccessBlock": Severity.CRITICAL,
    "PutPublicAccessBlock": Severity.INFO,
    # IAM
    "CreateLoginProfile": Severity.MEDIUM,
    "UpdateLoginProfile": Severity.MEDIUM,
    "CreateUser": Severity.LOW,
}

_DEFAULT_SEVERITY = Severity.INFO


def _extract_resource_id(detail: dict) -> str:
    """
    Best-effort extraction of the primary resource ID from a CloudTrail
    event detail block. Each service puts the resource in a different place.
    """
    req = detail.get("requestParameters") or {}
    resp = detail.get("responseElements") or {}

    # EC2 security groups
    group_id = req.get("groupId") or resp.get("groupId")
    if group_id:
        return group_id

    # S3 buckets
    bucket = req.get("bucketName")
    if bucket:
        return bucket

    # IAM users
    user_name = req.get("userName")
    if user_name:
        return user_name

    # Fall back to the ARN of the first resource listed by CloudTrail
    resources = detail.get("resources") or []
    if resources:
        return resources[0].get("ARN", "unknown")

    return "unknown"


def _build_finding(event: dict) -> Finding:
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "UnknownEvent")
    source = event.get("source", "aws.unknown")          # e.g. "aws.ec2"
    service = source.split(".")[-1]                       # e.g. "ec2"
    region = detail.get("awsRegion") or event.get("region", os.environ["AWS_REGION"])
    account_id = detail.get("userIdentity", {}).get("accountId", os.environ.get("AWS_ACCOUNT_ID", "unknown"))

    return Finding(
        service=service,
        finding_type=event_name.upper(),
        severity=_SEVERITY_MAP.get(event_name, _DEFAULT_SEVERITY),
        source=FindingSource.CLOUDTRAIL,
        resource_id=_extract_resource_id(detail),
        description=f"CloudTrail event: {event_name} on {service}",
        region=region,
        account_id=account_id,
        status=FindingStatus.DETECTED,
        raw_event_summary={
            "eventName": event_name,
            "eventSource": detail.get("eventSource", ""),
            "userAgent": detail.get("userAgent", ""),
            "sourceIPAddress": detail.get("sourceIPAddress", ""),
            "userIdentityType": detail.get("userIdentity", {}).get("type", ""),
        },
    )


def handler(event: dict[str, Any], context: Any) -> dict:
    logger.info("event-ingestor invoked", extra={"context": {
        "source": event.get("source"),
        "detail_type": event.get("detail-type"),
    }})

    try:
        finding = _build_finding(event)
        table = FindingsTable()
        table.put_finding(finding)

        logger.info("Finding stored", extra={"context": {
            "finding_id": finding.finding_id,
            "finding_type": finding.finding_type,
            "severity": finding.severity.value,
            "resource_id": finding.resource_id,
        }})

        return {"statusCode": 200, "finding_id": finding.finding_id}

    except Exception as exc:
        logger.error("event-ingestor failed", extra={"context": {"error": str(exc)}})
        raise

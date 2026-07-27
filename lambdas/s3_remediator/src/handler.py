"""
s3-remediator Lambda

Triggered by EventBridge on S3 bucket policy/ACL/public-access events.

If a bucket's public access block has been disabled or a public-granting
policy/ACL has been applied, this Lambda re-enables the public access
block on that bucket and records a REMEDIATED finding in DynamoDB.

Auto-remediation is conservative: it only re-enables the AWS-managed
public access block (the four-flag setting). It does not attempt to
rewrite bucket policies or ACLs — those require understanding intent
and are flagged with NO_AUTO_REMEDIATION status for human review.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from lambdas.shared.dynamo_client import FindingsTable
from lambdas.shared.logger import get_logger
from lambdas.shared.models import Finding, FindingSource, FindingStatus, Severity

logger = get_logger("s3-remediator")

# Events where we can auto-remediate (public access block removed/misconfigured)
AUTO_REMEDIABLE = {"DeletePublicAccessBlock", "PutPublicAccessBlock"}

# Events we flag but don't auto-remediate (policy/ACL intent is unclear)
FLAG_ONLY = {"PutBucketPolicy", "PutBucketAcl"}

FULL_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def _is_public_access_blocked(s3_client, bucket: str) -> bool:
    """Return True if all four public access block flags are enabled."""
    try:
        resp = s3_client.get_public_access_block(Bucket=bucket)
        config = resp.get("PublicAccessBlockConfiguration", {})
        return all([
            config.get("BlockPublicAcls", False),
            config.get("IgnorePublicAcls", False),
            config.get("BlockPublicPolicy", False),
            config.get("RestrictPublicBuckets", False),
        ])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return False
        raise


def _enable_public_access_block(s3_client, bucket: str) -> None:
    s3_client.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration=FULL_BLOCK,
    )


def handler(event: dict[str, Any], context: Any) -> dict:
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "Unknown")
    region = detail.get("awsRegion", os.environ.get("AWS_REGION", "us-east-1"))
    account_id = detail.get("userIdentity", {}).get("accountId", "unknown")
    bucket = (detail.get("requestParameters") or {}).get("bucketName", "unknown")

    logger.info("s3-remediator invoked", extra={"context": {
        "event_name": event_name,
        "bucket": bucket,
        "region": region,
    }})

    if bucket == "unknown":
        logger.warning("Could not extract bucket name — skipping")
        return {"statusCode": 200, "action": "skipped", "reason": "no_bucket_name"}

    s3 = boto3.client("s3", region_name=region)
    table = FindingsTable()

    # --- Events that need policy/ACL human review only ---
    if event_name in FLAG_ONLY:
        finding = Finding(
            service="s3",
            finding_type=f"S3_{event_name.upper()}_DETECTED",
            severity=Severity.HIGH,
            source=FindingSource.CLOUDTRAIL,
            resource_id=bucket,
            description=(
                f"S3 bucket {bucket} had {event_name} applied. "
                "Manual review required — auto-remediation not performed for policy/ACL changes."
            ),
            region=region,
            account_id=account_id,
            status=FindingStatus.NO_AUTO_REMEDIATION,
            raw_event_summary={"eventName": event_name},
        )
        table.put_finding(finding)
        return {
            "statusCode": 200,
            "action": "flagged",
            "bucket": bucket,
            "finding_id": finding.finding_id,
        }

    # --- Public access block events — check and re-enable if needed ---
    if event_name not in AUTO_REMEDIABLE:
        logger.info("Unhandled event type — skipping", extra={"context": {"event_name": event_name}})
        return {"statusCode": 200, "action": "skipped", "reason": "unhandled_event"}

    already_blocked = _is_public_access_blocked(s3, bucket)

    if already_blocked:
        logger.info("Public access already blocked", extra={"context": {"bucket": bucket}})
        return {"statusCode": 200, "action": "clean", "bucket": bucket}

    try:
        _enable_public_access_block(s3, bucket)
    except ClientError as exc:
        logger.error("Failed to re-enable public access block", extra={"context": {
            "bucket": bucket, "error": str(exc),
        }})
        finding = Finding(
            service="s3",
            finding_type="S3_PUBLIC_ACCESS_BLOCK_REMEDIATION_FAILED",
            severity=Severity.CRITICAL,
            source=FindingSource.CLOUDTRAIL,
            resource_id=bucket,
            description=f"Failed to re-enable public access block on {bucket}: {exc}",
            region=region,
            account_id=account_id,
            status=FindingStatus.REMEDIATION_FAILED,
            raw_event_summary={"eventName": event_name, "error": str(exc)},
        )
        table.put_finding(finding)
        raise

    finding = Finding(
        service="s3",
        finding_type="S3_PUBLIC_ACCESS_BLOCK_RESTORED",
        severity=Severity.CRITICAL,
        source=FindingSource.CLOUDTRAIL,
        resource_id=bucket,
        description=f"Public access block was disabled on {bucket} — re-enabled automatically.",
        region=region,
        account_id=account_id,
        status=FindingStatus.REMEDIATED,
        remediation_action=f"put_public_access_block on {bucket} (all four flags enabled)",
        remediated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        raw_event_summary={"eventName": event_name},
    )
    table.put_finding(finding)

    logger.info("Public access block restored", extra={"context": {"bucket": bucket}})
    return {
        "statusCode": 200,
        "action": "remediated",
        "bucket": bucket,
        "finding_id": finding.finding_id,
    }

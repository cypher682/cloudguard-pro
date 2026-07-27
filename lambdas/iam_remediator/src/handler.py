"""
iam-remediator Lambda

Triggered by EventBridge on IAM CreateLoginProfile, UpdateLoginProfile,
and CreateUser events.

Logic:
- If a user now has console access (login profile exists) but no MFA
  device enrolled, disable their console access immediately and record
  a REMEDIATED finding.
- Root account usage is detected separately (no auto-remediation —
  too sensitive) and recorded as NO_AUTO_REMEDIATION with CRITICAL severity.

This is a conservative remediator: it only disables console access
when MFA is provably absent. It does not touch programmatic access keys.
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

logger = get_logger("iam-remediator")


def _has_mfa(iam_client, username: str) -> bool:
    """Return True if the IAM user has at least one MFA device enrolled."""
    try:
        resp = iam_client.list_mfa_devices(UserName=username)
        return len(resp.get("MFADevices", [])) > 0
    except ClientError as exc:
        logger.error("Failed to list MFA devices", extra={"context": {
            "username": username, "error": str(exc),
        }})
        return True  # fail-safe: assume MFA present to avoid false-positive disable


def _has_login_profile(iam_client, username: str) -> bool:
    """Return True if the IAM user has console access (login profile)."""
    try:
        iam_client.get_login_profile(UserName=username)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise


def _disable_console_access(iam_client, username: str) -> None:
    """Delete the login profile, revoking console access."""
    iam_client.delete_login_profile(UserName=username)


def _is_root_event(detail: dict) -> bool:
    user_type = detail.get("userIdentity", {}).get("type", "")
    return user_type == "Root"


def handler(event: dict[str, Any], context: Any) -> dict:
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "Unknown")
    region = detail.get("awsRegion", os.environ.get("AWS_REGION", "us-east-1"))
    account_id = detail.get("userIdentity", {}).get("accountId", "unknown")
    username = (detail.get("requestParameters") or {}).get("userName", "unknown")

    logger.info("iam-remediator invoked", extra={"context": {
        "event_name": event_name,
        "username": username,
    }})

    table = FindingsTable()

    # --- Root account usage: alert only, no auto-remediation ---
    if _is_root_event(detail):
        finding = Finding(
            service="iam",
            finding_type="ROOT_ACCOUNT_USAGE_DETECTED",
            severity=Severity.CRITICAL,
            source=FindingSource.CLOUDTRAIL,
            resource_id="root",
            description=(
                f"Root account was used to perform {event_name}. "
                "Immediate review required — no auto-remediation applied."
            ),
            region=region,
            account_id=account_id,
            status=FindingStatus.NO_AUTO_REMEDIATION,
            raw_event_summary={"eventName": event_name},
        )
        table.put_finding(finding)
        logger.warning("Root account usage detected — SNS alert only")
        return {
            "statusCode": 200,
            "action": "flagged_root_usage",
            "finding_id": finding.finding_id,
        }

    if username == "unknown":
        logger.warning("Could not extract username — skipping")
        return {"statusCode": 200, "action": "skipped", "reason": "no_username"}

    iam = boto3.client("iam", region_name=region)

    # Only act on users who have a login profile (console access)
    if not _has_login_profile(iam, username):
        logger.info("User has no login profile — no action needed", extra={"context": {"username": username}})
        return {"statusCode": 200, "action": "clean", "username": username}

    # Check MFA
    if _has_mfa(iam, username):
        logger.info("User has MFA — no action needed", extra={"context": {"username": username}})
        return {"statusCode": 200, "action": "clean", "username": username}

    # Console access exists, MFA absent — disable console access
    try:
        _disable_console_access(iam, username)
    except ClientError as exc:
        logger.error("Failed to disable console access", extra={"context": {
            "username": username, "error": str(exc),
        }})
        finding = Finding(
            service="iam",
            finding_type="IAM_CONSOLE_ACCESS_DISABLE_FAILED",
            severity=Severity.CRITICAL,
            source=FindingSource.CLOUDTRAIL,
            resource_id=username,
            description=f"Failed to disable console access for {username} (no MFA): {exc}",
            region=region,
            account_id=account_id,
            status=FindingStatus.REMEDIATION_FAILED,
            raw_event_summary={"eventName": event_name, "error": str(exc)},
        )
        table.put_finding(finding)
        raise

    finding = Finding(
        service="iam",
        finding_type="IAM_CONSOLE_ACCESS_DISABLED_NO_MFA",
        severity=Severity.HIGH,
        source=FindingSource.CLOUDTRAIL,
        resource_id=username,
        description=(
            f"IAM user {username} had console access with no MFA enrolled. "
            "Console access disabled automatically."
        ),
        region=region,
        account_id=account_id,
        status=FindingStatus.REMEDIATED,
        remediation_action=f"delete_login_profile for {username}",
        remediated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        raw_event_summary={"eventName": event_name},
    )
    table.put_finding(finding)

    logger.info("Console access disabled for user without MFA", extra={"context": {"username": username}})
    return {
        "statusCode": 200,
        "action": "remediated",
        "username": username,
        "finding_id": finding.finding_id,
    }

"""
security-hub-sync Lambda

Triggered daily by EventBridge schedule.
Pulls aggregated findings from AWS Security Hub (ACTIVE, non-suppressed)
and writes them to the cloudguard DynamoDB findings table so they appear
alongside CloudTrail-detected and CIS-scanner findings in a single view.

Only NEW findings (not previously stored) are written. The finding_id
used is the Security Hub finding ID (deterministic), so re-runs are
idempotent via DynamoDB conditional writes.

Severity mapping: Security Hub uses INFORMATIONAL/LOW/MEDIUM/HIGH/CRITICAL
which maps directly to our Severity enum.
"""

from __future__ import annotations

import os
from typing import Any

import boto3
from botocore.exceptions import ClientError

from lambdas.shared.dynamo_client import FindingsTable
from lambdas.shared.logger import get_logger
from lambdas.shared.models import Finding, FindingSource, FindingStatus, Severity

logger = get_logger("security-hub-sync")

_SEVERITY_MAP = {
    "INFORMATIONAL": Severity.INFO,
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


def _map_severity(sh_severity: str) -> Severity:
    return _SEVERITY_MAP.get(sh_severity.upper(), Severity.INFO)


def _sh_finding_to_finding(sh: dict, region: str, account_id: str) -> Finding:
    """Convert a Security Hub finding dict to a cloudguard Finding."""
    sh_id = sh.get("Id", "unknown")
    title = sh.get("Title", "Unknown Finding")
    description = sh.get("Description", title)
    severity_label = sh.get("Severity", {}).get("Label", "INFORMATIONAL")
    status = sh.get("Workflow", {}).get("Status", "NEW")
    product_name = sh.get("ProductName", "SecurityHub")
    resources = sh.get("Resources", [{}])
    resource_id = resources[0].get("Id", "unknown") if resources else "unknown"
    resource_type = resources[0].get("Type", "unknown") if resources else "unknown"
    service = resource_type.split("::")[-1].lower() if "::" in resource_type else "aws"
    created_at = sh.get("CreatedAt", "")

    return Finding(
        finding_id=_stable_id(sh_id),
        service=service,
        finding_type=f"SECURITYHUB_{title.upper().replace(' ', '_')[:60]}",
        severity=_map_severity(severity_label),
        source=FindingSource.SECURITY_HUB,
        resource_id=resource_id,
        description=f"[{product_name}] {description}",
        region=region,
        account_id=account_id,
        status=FindingStatus.DETECTED if status == "NEW" else FindingStatus.ACKNOWLEDGED,
        created_at=created_at or Finding.__dataclass_fields__["created_at"].default_factory(),
        raw_event_summary={
            "securityHubId": sh_id,
            "productName": product_name,
            "workflowStatus": status,
        },
    )


def _stable_id(sh_id: str) -> str:
    """
    Convert the Security Hub finding ARN to a shorter stable ID for DynamoDB.
    We take the last 36 chars which typically contain the UUID portion.
    """
    return sh_id[-36:] if len(sh_id) > 36 else sh_id


def _get_sh_findings(sh_client, max_results: int = 100) -> list[dict]:
    """
    Pull active, non-suppressed Security Hub findings.
    Paginates up to max_results total.
    """
    findings = []
    filters = {
        "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    }

    paginator = sh_client.get_paginator("get_findings")
    for page in paginator.paginate(Filters=filters, MaxResults=min(max_results, 100)):
        findings.extend(page.get("Findings", []))
        if len(findings) >= max_results:
            break

    return findings[:max_results]


def handler(event: dict[str, Any], context: Any) -> dict:
    region = os.environ.get("AWS_REGION", "us-east-1")
    account_id = os.environ.get("AWS_ACCOUNT_ID", "unknown")

    logger.info("security-hub-sync starting", extra={"context": {"region": region}})

    sh = boto3.client("securityhub", region_name=region)
    table = FindingsTable()

    try:
        sh_findings = _get_sh_findings(sh)
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "InvalidAccessException":
            logger.error(
                "Security Hub is not enabled in this region — enable it first",
                extra={"context": {"region": region, "error": str(exc)}},
            )
            return {"statusCode": 400, "error": "SecurityHub not enabled", "synced": 0}
        raise

    synced = 0
    skipped = 0

    for sh_finding in sh_findings:
        try:
            finding = _sh_finding_to_finding(sh_finding, region, account_id)
            table.put_finding(finding)
            synced += 1
        except Exception as exc:
            logger.error("Failed to sync Security Hub finding", extra={"context": {
                "sh_id": sh_finding.get("Id", "unknown"),
                "error": str(exc),
            }})
            skipped += 1

    logger.info("security-hub-sync complete", extra={"context": {
        "total_from_sh": len(sh_findings),
        "synced": synced,
        "skipped": skipped,
    }})

    return {"statusCode": 200, "synced": synced, "skipped": skipped}

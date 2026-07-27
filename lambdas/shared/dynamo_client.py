"""
Thin DynamoDB client wrapper for the findings table.

All Lambdas use this instead of calling boto3 directly, so the table
name resolution and error handling stays consistent, and moto-based
unit tests can patch a single point.
"""

from __future__ import annotations

import os

import boto3
from botocore.exceptions import ClientError

from .logger import get_logger
from .models import Finding, FindingStatus

logger = get_logger("shared.dynamo_client")


class FindingsTable:
    def __init__(self, table_name: str | None = None, region: str | None = None):
        self.table_name = table_name or os.environ["FINDINGS_TABLE_NAME"]
        self.region = region or os.environ.get("AWS_REGION", "us-east-1")
        self._resource = boto3.resource("dynamodb", region_name=self.region)
        self._table = self._resource.Table(self.table_name)

    def put_finding(self, finding: Finding) -> None:
        """Write a new finding. Triggers DynamoDB Streams -> finding-notifier."""
        try:
            self._table.put_item(Item=finding.to_item())
            logger.info(
                "Finding written",
                extra={
                    "context": {
                        "finding_id": finding.finding_id,
                        "finding_type": finding.finding_type,
                        "severity": finding.severity.value,
                    }
                },
            )
        except ClientError as exc:
            logger.error(
                "Failed to write finding",
                extra={"context": {"error": str(exc), "finding_id": finding.finding_id}},
            )
            raise

    def update_status(
        self,
        finding_id: str,
        created_at: str,
        status: FindingStatus,
        remediation_action: str | None = None,
        remediated_at: str | None = None,
    ) -> None:
        """Update a finding's remediation status after a remediator Lambda acts on it."""
        update_expr = "SET #status = :status"
        expr_names = {"#status": "status"}
        expr_values: dict = {":status": status.value}

        if remediation_action is not None:
            update_expr += ", remediation_action = :action"
            expr_values[":action"] = remediation_action

        if remediated_at is not None:
            update_expr += ", remediated_at = :remediated_at"
            expr_values[":remediated_at"] = remediated_at

        try:
            self._table.update_item(
                Key={"finding_id": finding_id, "created_at": created_at},
                UpdateExpression=update_expr,
                ExpressionAttributeNames=expr_names,
                ExpressionAttributeValues=expr_values,
            )
            logger.info(
                "Finding status updated",
                extra={"context": {"finding_id": finding_id, "status": status.value}},
            )
        except ClientError as exc:
            logger.error(
                "Failed to update finding status",
                extra={"context": {"error": str(exc), "finding_id": finding_id}},
            )
            raise

    def get_recent_by_severity(self, severity: str, limit: int = 25) -> list[dict]:
        """Query the severity-index GSI for recent findings of a given severity."""
        response = self._table.query(
            IndexName="severity-index",
            KeyConditionExpression=boto3.dynamodb.conditions.Key("severity").eq(severity),
            ScanIndexForward=False,  # most recent first
            Limit=limit,
        )
        return response.get("Items", [])

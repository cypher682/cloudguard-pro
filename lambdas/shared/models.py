"""
Finding data model — the single schema every detector and remediator
Lambda writes to and reads from in DynamoDB.

Table design (see terraform/modules/dynamodb):
  Partition key: finding_id   (string, UUID)
  Sort key:      created_at   (string, ISO8601)
  GSI:           severity-index   (partition: severity, sort: created_at)
  GSI:           service-index    (partition: service, sort: created_at)

Streams enabled on the table -> finding-notifier Lambda triggers on INSERT.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, Enum):
    DETECTED = "DETECTED"
    REMEDIATED = "REMEDIATED"
    REMEDIATION_FAILED = "REMEDIATION_FAILED"
    NO_AUTO_REMEDIATION = "NO_AUTO_REMEDIATION"  # e.g. root account usage
    ACKNOWLEDGED = "ACKNOWLEDGED"


class FindingSource(str, Enum):
    CLOUDTRAIL = "CLOUDTRAIL"
    CONFIG_RULE = "CONFIG_RULE"
    CIS_SCANNER = "CIS_SCANNER"
    SECURITY_HUB = "SECURITY_HUB"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class Finding:
    """
    A single security finding. This is the canonical record stored in
    DynamoDB. All Lambdas construct this object rather than building
    raw dicts, so the schema can't silently drift between functions.
    """

    service: str                     # e.g. "ec2", "s3", "iam"
    finding_type: str                # e.g. "OPEN_SSH_INGRESS"
    severity: Severity
    source: FindingSource
    resource_id: str                 # e.g. sg-0123, bucket name, IAM user
    description: str
    region: str
    account_id: str

    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=_utc_now_iso)
    status: FindingStatus = FindingStatus.DETECTED
    remediation_action: str | None = None
    remediated_at: str | None = None
    raw_event_summary: dict | None = None
    cis_check_id: str | None = None

    def to_item(self) -> dict:
        """Convert to a DynamoDB-writable dict (enums -> their string values)."""
        item = asdict(self)
        item["severity"] = self.severity.value
        item["source"] = self.source.value
        item["status"] = self.status.value
        # DynamoDB rejects None values cleanly only if we strip them
        return {k: v for k, v in item.items() if v is not None}

    @staticmethod
    def from_item(item: dict) -> "Finding":
        """Reconstruct a Finding from a DynamoDB item."""
        return Finding(
            service=item["service"],
            finding_type=item["finding_type"],
            severity=Severity(item["severity"]),
            source=FindingSource(item["source"]),
            resource_id=item["resource_id"],
            description=item["description"],
            region=item["region"],
            account_id=item["account_id"],
            finding_id=item["finding_id"],
            created_at=item["created_at"],
            status=FindingStatus(item.get("status", FindingStatus.DETECTED.value)),
            remediation_action=item.get("remediation_action"),
            remediated_at=item.get("remediated_at"),
            raw_event_summary=item.get("raw_event_summary"),
            cis_check_id=item.get("cis_check_id"),
        )

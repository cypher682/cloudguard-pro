"""
cis-scanner Lambda

Triggered on a schedule (every 6 hours via EventBridge).
Runs a subset of CIS AWS Foundations Benchmark v1.4 checks that have
no equivalent AWS-managed Config rule, or where we want programmatic
control of the finding format.

CIS checks implemented:
  1.4  — Root account has no active access keys
  1.5  — MFA enabled for root account (via IAM summary)
  1.10 — MFA enabled for all IAM users with console access
  3.1  — CloudTrail enabled in all regions
  3.3  — CloudTrail log file validation enabled
  4.1  — No unrestricted SSH (port 22) in any security group
  4.2  — No unrestricted RDP (port 3389) in any security group

Each check writes a Finding to DynamoDB — DETECTED if failing,
INFO/ACKNOWLEDGED if passing (so the table shows a full scan history).
"""

from __future__ import annotations

import os
from typing import Any

import boto3
from botocore.exceptions import ClientError

from lambdas.shared.dynamo_client import FindingsTable
from lambdas.shared.logger import get_logger
from lambdas.shared.models import Finding, FindingSource, FindingStatus, Severity

logger = get_logger("cis-scanner")

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _finding(
    cis_id: str,
    service: str,
    finding_type: str,
    severity: Severity,
    resource_id: str,
    description: str,
    region: str,
    account_id: str,
    status: FindingStatus = FindingStatus.DETECTED,
) -> Finding:
    f = Finding(
        service=service,
        finding_type=finding_type,
        severity=severity,
        source=FindingSource.CIS_SCANNER,
        resource_id=resource_id,
        description=description,
        region=region,
        account_id=account_id,
        status=status,
        cis_check_id=cis_id,
    )
    return f


# ── CIS Checks ───────────────────────────────────────────────────────────────

def check_1_4_root_no_access_keys(iam_client, region: str, account_id: str) -> list[Finding]:
    """CIS 1.4 — Root account should have no active access keys."""
    summary = iam_client.get_account_summary()["SummaryMap"]
    key_count = summary.get("AccountAccessKeysPresent", 0)

    if key_count > 0:
        return [_finding(
            cis_id="1.4",
            service="iam",
            finding_type="CIS_1_4_ROOT_ACCESS_KEYS_PRESENT",
            severity=Severity.CRITICAL,
            resource_id="root",
            description=f"Root account has {key_count} active access key(s). CIS 1.4 requires none.",
            region=region,
            account_id=account_id,
        )]

    return [_finding(
        cis_id="1.4",
        service="iam",
        finding_type="CIS_1_4_PASS",
        severity=Severity.INFO,
        resource_id="root",
        description="CIS 1.4 PASS — root account has no active access keys.",
        region=region,
        account_id=account_id,
        status=FindingStatus.ACKNOWLEDGED,
    )]


def check_1_5_root_mfa(iam_client, region: str, account_id: str) -> list[Finding]:
    """CIS 1.5 — MFA should be enabled on the root account."""
    summary = iam_client.get_account_summary()["SummaryMap"]
    mfa_active = summary.get("AccountMFAEnabled", 0)

    if not mfa_active:
        return [_finding(
            cis_id="1.5",
            service="iam",
            finding_type="CIS_1_5_ROOT_MFA_DISABLED",
            severity=Severity.CRITICAL,
            resource_id="root",
            description="Root account does not have MFA enabled. CIS 1.5 requires MFA on root.",
            region=region,
            account_id=account_id,
        )]

    return [_finding(
        cis_id="1.5",
        service="iam",
        finding_type="CIS_1_5_PASS",
        severity=Severity.INFO,
        resource_id="root",
        description="CIS 1.5 PASS — root account has MFA enabled.",
        region=region,
        account_id=account_id,
        status=FindingStatus.ACKNOWLEDGED,
    )]


def check_1_10_iam_users_mfa(iam_client, region: str, account_id: str) -> list[Finding]:
    """CIS 1.10 — All IAM users with console access must have MFA."""
    paginator = iam_client.get_paginator("list_users")
    findings = []

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]

            # Check if user has a login profile (console access)
            try:
                iam_client.get_login_profile(UserName=username)
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "NoSuchEntity":
                    continue
                raise

            # Has console access — check MFA
            mfa_resp = iam_client.list_mfa_devices(UserName=username)
            if not mfa_resp.get("MFADevices"):
                findings.append(_finding(
                    cis_id="1.10",
                    service="iam",
                    finding_type="CIS_1_10_USER_NO_MFA",
                    severity=Severity.HIGH,
                    resource_id=username,
                    description=f"IAM user {username} has console access but no MFA device. CIS 1.10.",
                    region=region,
                    account_id=account_id,
                ))

    return findings


def check_3_1_cloudtrail_enabled(ct_client, region: str, account_id: str) -> list[Finding]:
    """CIS 3.1 — CloudTrail should be enabled and logging."""
    trails = ct_client.describe_trails(includeShadowTrails=False).get("trailList", [])

    if not trails:
        return [_finding(
            cis_id="3.1",
            service="cloudtrail",
            finding_type="CIS_3_1_CLOUDTRAIL_NOT_ENABLED",
            severity=Severity.CRITICAL,
            resource_id=region,
            description=f"No CloudTrail trails found in {region}. CIS 3.1 requires CloudTrail enabled in all regions.",
            region=region,
            account_id=account_id,
        )]

    findings = []
    for trail in trails:
        trail_name = trail["Name"]
        status = ct_client.get_trail_status(Name=trail_name)
        if not status.get("IsLogging", False):
            findings.append(_finding(
                cis_id="3.1",
                service="cloudtrail",
                finding_type="CIS_3_1_CLOUDTRAIL_NOT_LOGGING",
                severity=Severity.CRITICAL,
                resource_id=trail_name,
                description=f"CloudTrail trail {trail_name} exists but is not actively logging.",
                region=region,
                account_id=account_id,
            ))

    if not findings:
        findings.append(_finding(
            cis_id="3.1",
            service="cloudtrail",
            finding_type="CIS_3_1_PASS",
            severity=Severity.INFO,
            resource_id=region,
            description="CIS 3.1 PASS — CloudTrail is enabled and logging.",
            region=region,
            account_id=account_id,
            status=FindingStatus.ACKNOWLEDGED,
        ))

    return findings


def check_3_3_cloudtrail_log_validation(ct_client, region: str, account_id: str) -> list[Finding]:
    """CIS 3.3 — CloudTrail log file validation must be enabled."""
    trails = ct_client.describe_trails(includeShadowTrails=False).get("trailList", [])
    findings = []

    for trail in trails:
        if not trail.get("LogFileValidationEnabled", False):
            findings.append(_finding(
                cis_id="3.3",
                service="cloudtrail",
                finding_type="CIS_3_3_LOG_VALIDATION_DISABLED",
                severity=Severity.MEDIUM,
                resource_id=trail["Name"],
                description=f"CloudTrail trail {trail['Name']} does not have log file validation enabled.",
                region=region,
                account_id=account_id,
            ))

    if not findings:
        findings.append(_finding(
            cis_id="3.3",
            service="cloudtrail",
            finding_type="CIS_3_3_PASS",
            severity=Severity.INFO,
            resource_id=region,
            description="CIS 3.3 PASS — all trails have log file validation enabled.",
            region=region,
            account_id=account_id,
            status=FindingStatus.ACKNOWLEDGED,
        ))

    return findings


def check_4_x_unrestricted_ports(ec2_client, region: str, account_id: str) -> list[Finding]:
    """CIS 4.1 + 4.2 — No unrestricted SSH (22) or RDP (3389) ingress."""
    paginator = ec2_client.get_paginator("describe_security_groups")
    findings = []
    dangerous_ports = {22: "CIS 4.1 (SSH)", 3389: "CIS 4.2 (RDP)"}

    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            group_id = sg["GroupId"]
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 0)
                try:
                    port_range = set(range(int(from_port), int(to_port) + 1))
                except (TypeError, ValueError):
                    continue

                for port, label in dangerous_ports.items():
                    if port not in port_range:
                        continue

                    open_ipv4 = any(
                        r.get("CidrIp") in OPEN_CIDRS
                        for r in perm.get("IpRanges", [])
                    )
                    open_ipv6 = any(
                        r.get("CidrIpv6") in OPEN_CIDRS
                        for r in perm.get("Ipv6Ranges", [])
                    )

                    if open_ipv4 or open_ipv6:
                        cis_id = "4.1" if port == 22 else "4.2"
                        findings.append(_finding(
                            cis_id=cis_id,
                            service="ec2",
                            finding_type=f"CIS_{cis_id.replace('.', '_')}_UNRESTRICTED_PORT_{port}",
                            severity=Severity.HIGH,
                            resource_id=group_id,
                            description=(
                                f"Security group {group_id} allows unrestricted access on port {port}. {label}."
                            ),
                            region=region,
                            account_id=account_id,
                        ))

    return findings


# ── Handler ──────────────────────────────────────────────────────────────────

def handler(event: dict[str, Any], context: Any) -> dict:
    region = os.environ.get("AWS_REGION", "us-east-1")
    account_id = os.environ.get("AWS_ACCOUNT_ID", "unknown")

    logger.info("cis-scanner starting", extra={"context": {"region": region}})

    iam = boto3.client("iam", region_name=region)
    ct = boto3.client("cloudtrail", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    table = FindingsTable()

    all_findings: list[Finding] = []

    checks = [
        ("1.4", lambda: check_1_4_root_no_access_keys(iam, region, account_id)),
        ("1.5", lambda: check_1_5_root_mfa(iam, region, account_id)),
        ("1.10", lambda: check_1_10_iam_users_mfa(iam, region, account_id)),
        ("3.1", lambda: check_3_1_cloudtrail_enabled(ct, region, account_id)),
        ("3.3", lambda: check_3_3_cloudtrail_log_validation(ct, region, account_id)),
        ("4.x", lambda: check_4_x_unrestricted_ports(ec2, region, account_id)),
    ]

    for check_id, check_fn in checks:
        try:
            findings = check_fn()
            for f in findings:
                table.put_finding(f)
            all_findings.extend(findings)
            logger.info(f"CIS {check_id} complete", extra={"context": {
                "findings": len(findings),
                "statuses": [f.status.value for f in findings],
            }})
        except Exception as exc:
            logger.error(f"CIS {check_id} check failed", extra={"context": {"error": str(exc)}})

    failed = [f for f in all_findings if f.status == FindingStatus.DETECTED]
    passed = [f for f in all_findings if f.status == FindingStatus.ACKNOWLEDGED]

    logger.info("cis-scanner complete", extra={"context": {
        "total": len(all_findings),
        "failed": len(failed),
        "passed": len(passed),
    }})

    return {
        "statusCode": 200,
        "total_checks": len(all_findings),
        "failed": len(failed),
        "passed": len(passed),
        "failed_check_ids": [f.cis_check_id for f in failed],
    }

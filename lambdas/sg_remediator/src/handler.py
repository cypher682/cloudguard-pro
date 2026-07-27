"""
sg-remediator Lambda

Triggered by EventBridge on AuthorizeSecurityGroupIngress and
ModifySecurityGroupRules events.

Checks whether the modified security group now contains any ingress rules
allowing 0.0.0.0/0 or ::/0 on port 22 (SSH) or port 3389 (RDP).
If found, revokes the offending rules immediately and updates the
DynamoDB finding status.

Root account usage or rules on port 22/3389 with ANY source are flagged
as CRITICAL and remediated — the only exception is rules that are
already restricted to specific CIDRs (not 0.0.0.0/0), which are left
alone as intentional.
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

logger = get_logger("sg-remediator")

DANGEROUS_PORTS = {22, 3389}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _is_dangerous_rule(rule: dict) -> bool:
    """
    Return True if a security group ingress rule allows unrestricted
    access (0.0.0.0/0 or ::/0) on SSH or RDP ports.
    """
    from_port = rule.get("fromPort", rule.get("FromPort", 0))
    to_port = rule.get("toPort", rule.get("ToPort", 0))

    # Port range check — flag if the range includes 22 or 3389
    try:
        port_range = set(range(int(from_port), int(to_port) + 1))
    except (TypeError, ValueError):
        return False

    if not port_range.intersection(DANGEROUS_PORTS):
        return False

    # CIDR check — only flag unrestricted sources
    ip_ranges = rule.get("ipRanges", rule.get("IpRanges", []))
    ipv6_ranges = rule.get("ipv6Ranges", rule.get("Ipv6Ranges", []))

    for r in ip_ranges:
        cidr = r if isinstance(r, str) else r.get("cidrIp", r.get("CidrIp", ""))
        if cidr in OPEN_CIDRS:
            return True

    for r in ipv6_ranges:
        cidr = r if isinstance(r, str) else r.get("cidrIpv6", r.get("CidrIpv6", ""))
        if cidr in OPEN_CIDRS:
            return True

    return False


def _revoke_dangerous_rules(ec2_client, group_id: str, region: str) -> list[dict]:
    """
    Describe the current ingress rules for the SG, identify dangerous
    ones, revoke them, and return the list of revoked rules.
    """
    try:
        resp = ec2_client.describe_security_groups(GroupIds=[group_id])
    except ClientError as exc:
        logger.error("Failed to describe SG", extra={"context": {
            "group_id": group_id, "error": str(exc),
        }})
        raise

    groups = resp.get("SecurityGroups", [])
    if not groups:
        logger.warning("SG not found", extra={"context": {"group_id": group_id}})
        return []

    sg = groups[0]
    ip_permissions = sg.get("IpPermissions", [])
    revoked = []

    for perm in ip_permissions:
        # Build a sub-permission containing only the dangerous CIDR ranges
        dangerous_ipv4 = [
            r for r in perm.get("IpRanges", [])
            if r.get("CidrIp") in OPEN_CIDRS
        ]
        dangerous_ipv6 = [
            r for r in perm.get("Ipv6Ranges", [])
            if r.get("CidrIpv6") in OPEN_CIDRS
        ]

        from_port = perm.get("FromPort", 0)
        to_port = perm.get("ToPort", 0)
        try:
            port_range = set(range(int(from_port), int(to_port) + 1))
        except (TypeError, ValueError):
            continue

        if not port_range.intersection(DANGEROUS_PORTS):
            continue

        if not dangerous_ipv4 and not dangerous_ipv6:
            continue

        # Build the exact permission object to revoke
        revoke_perm = {
            "IpProtocol": perm.get("IpProtocol", "tcp"),
            "FromPort": from_port,
            "ToPort": to_port,
        }
        if dangerous_ipv4:
            revoke_perm["IpRanges"] = dangerous_ipv4
        if dangerous_ipv6:
            revoke_perm["Ipv6Ranges"] = dangerous_ipv6

        try:
            ec2_client.revoke_security_group_ingress(
                GroupId=group_id,
                IpPermissions=[revoke_perm],
            )
            revoked.append(revoke_perm)
            logger.info("Revoked dangerous SG rule", extra={"context": {
                "group_id": group_id,
                "from_port": from_port,
                "to_port": to_port,
                "cidr": str(dangerous_ipv4 + dangerous_ipv6),
            }})
        except ClientError as exc:
            logger.error("Failed to revoke SG rule", extra={"context": {
                "group_id": group_id, "error": str(exc),
            }})

    return revoked


def handler(event: dict[str, Any], context: Any) -> dict:
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "Unknown")
    region = detail.get("awsRegion", os.environ.get("AWS_REGION", "us-east-1"))
    account_id = detail.get("userIdentity", {}).get("accountId", "unknown")

    # Extract group ID from request or response parameters
    req = detail.get("requestParameters") or {}
    resp_el = detail.get("responseElements") or {}
    group_id = req.get("groupId") or resp_el.get("groupId") or "unknown"

    logger.info("sg-remediator invoked", extra={"context": {
        "event_name": event_name,
        "group_id": group_id,
        "region": region,
    }})

    if group_id == "unknown":
        logger.warning("Could not extract group_id from event — skipping")
        return {"statusCode": 200, "action": "skipped", "reason": "no_group_id"}

    ec2 = boto3.client("ec2", region_name=region)
    revoked = _revoke_dangerous_rules(ec2, group_id, region)

    table = FindingsTable()

    if revoked:
        finding = Finding(
            service="ec2",
            finding_type="OPEN_SSH_RDP_INGRESS_REVOKED",
            severity=Severity.CRITICAL,
            source=FindingSource.CLOUDTRAIL,
            resource_id=group_id,
            description=(
                f"Security group {group_id} had unrestricted SSH/RDP ingress. "
                f"{len(revoked)} rule(s) revoked automatically."
            ),
            region=region,
            account_id=account_id,
            status=FindingStatus.REMEDIATED,
            remediation_action=f"revoke_security_group_ingress on {group_id}",
            remediated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            raw_event_summary={"eventName": event_name, "revokedRules": len(revoked)},
        )
        table.put_finding(finding)

        return {
            "statusCode": 200,
            "action": "remediated",
            "group_id": group_id,
            "rules_revoked": len(revoked),
            "finding_id": finding.finding_id,
        }

    logger.info("No dangerous rules found", extra={"context": {"group_id": group_id}})
    return {"statusCode": 200, "action": "clean", "group_id": group_id}

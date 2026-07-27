"""
Tests for sg-remediator Lambda handler.
All AWS calls are moto-mocked — no live AWS required.
"""

import boto3
import pytest
from moto import mock_aws

from lambdas.sg_remediator.src.handler import (
    handler,
    _is_dangerous_rule,
    _revoke_dangerous_rules,
)


TABLE_NAME = "cloudguard-findings-test"
REGION = "us-east-1"


def _make_table():
    ddb = boto3.resource("dynamodb", region_name=REGION)
    table = ddb.create_table(
        TableName=TABLE_NAME,
        KeySchema=[
            {"AttributeName": "finding_id", "KeyType": "HASH"},
            {"AttributeName": "created_at", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "finding_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "S"},
            {"AttributeName": "severity", "AttributeType": "S"},
            {"AttributeName": "service", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "severity-index",
                "KeySchema": [
                    {"AttributeName": "severity", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "service-index",
                "KeySchema": [
                    {"AttributeName": "service", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    table.wait_until_exists()
    return table


def _make_sg(ec2_client, open_ssh=True, open_rdp=False, restricted=False):
    """Create a VPC + SG with configurable ingress rules."""
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]
    sg = ec2_client.create_security_group(
        GroupName="test-sg", Description="test", VpcId=vpc_id
    )
    group_id = sg["GroupId"]

    if open_ssh:
        ec2_client.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )

    if open_rdp:
        ec2_client.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )

    if restricted:
        ec2_client.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            }],
        )

    return group_id


def _make_event(group_id):
    return {
        "source": "aws.ec2",
        "detail-type": "AWS API Call via CloudTrail",
        "detail": {
            "eventName": "AuthorizeSecurityGroupIngress",
            "awsRegion": REGION,
            "userIdentity": {"accountId": "123456789012"},
            "requestParameters": {"groupId": group_id},
        },
    }


# --- Unit tests (no AWS) ---

def test_is_dangerous_rule_open_ssh():
    rule = {
        "fromPort": 22, "toPort": 22,
        "ipRanges": [{"CidrIp": "0.0.0.0/0"}],
        "ipv6Ranges": [],
    }
    assert _is_dangerous_rule(rule) is True


def test_is_dangerous_rule_open_rdp():
    rule = {
        "fromPort": 3389, "toPort": 3389,
        "ipRanges": [{"CidrIp": "0.0.0.0/0"}],
        "ipv6Ranges": [],
    }
    assert _is_dangerous_rule(rule) is True


def test_is_dangerous_rule_restricted_cidr():
    rule = {
        "fromPort": 22, "toPort": 22,
        "ipRanges": [{"CidrIp": "10.0.0.0/8"}],
        "ipv6Ranges": [],
    }
    assert _is_dangerous_rule(rule) is False


def test_is_dangerous_rule_safe_port():
    rule = {
        "fromPort": 443, "toPort": 443,
        "ipRanges": [{"CidrIp": "0.0.0.0/0"}],
        "ipv6Ranges": [],
    }
    assert _is_dangerous_rule(rule) is False


def test_is_dangerous_rule_ipv6():
    rule = {
        "fromPort": 22, "toPort": 22,
        "ipRanges": [],
        "ipv6Ranges": [{"CidrIpv6": "::/0"}],
    }
    assert _is_dangerous_rule(rule) is True


# --- Integration tests (moto) ---

@mock_aws
def test_handler_revokes_open_ssh():
    ec2 = boto3.client("ec2", region_name=REGION)
    _make_table()
    group_id = _make_sg(ec2, open_ssh=True)

    result = handler(_make_event(group_id), None)

    assert result["action"] == "remediated"
    assert result["rules_revoked"] == 1
    assert result["group_id"] == group_id

    # Verify rule was actually removed
    sg = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
    for perm in sg["IpPermissions"]:
        for r in perm.get("IpRanges", []):
            assert r["CidrIp"] != "0.0.0.0/0"


@mock_aws
def test_handler_revokes_open_rdp():
    ec2 = boto3.client("ec2", region_name=REGION)
    _make_table()
    group_id = _make_sg(ec2, open_ssh=False, open_rdp=True)

    result = handler(_make_event(group_id), None)

    assert result["action"] == "remediated"
    assert result["rules_revoked"] == 1


@mock_aws
def test_handler_leaves_restricted_rule_intact():
    ec2 = boto3.client("ec2", region_name=REGION)
    _make_table()
    group_id = _make_sg(ec2, open_ssh=False, restricted=True)

    result = handler(_make_event(group_id), None)

    assert result["action"] == "clean"

    # Restricted rule must still be present
    sg = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
    cidrs = [
        r["CidrIp"]
        for perm in sg["IpPermissions"]
        for r in perm.get("IpRanges", [])
    ]
    assert "10.0.0.0/8" in cidrs


@mock_aws
def test_handler_writes_finding_on_remediation():
    ec2 = boto3.client("ec2", region_name=REGION)
    table = _make_table()
    group_id = _make_sg(ec2, open_ssh=True)

    handler(_make_event(group_id), None)

    resp = table.scan()
    assert resp["Count"] == 1
    item = resp["Items"][0]
    assert item["status"] == "REMEDIATED"
    assert item["service"] == "ec2"
    assert "remediation_action" in item


@mock_aws
def test_handler_no_group_id_skips_gracefully():
    _make_table()
    event = {
        "source": "aws.ec2",
        "detail": {
            "eventName": "AuthorizeSecurityGroupIngress",
            "awsRegion": REGION,
            "userIdentity": {"accountId": "123456789012"},
            "requestParameters": {},
        },
    }
    result = handler(event, None)
    assert result["action"] == "skipped"

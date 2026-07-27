"""
Tests for cis-scanner Lambda handler.
All AWS calls are moto-mocked — no live AWS required.
"""

import boto3
import pytest
from moto import mock_aws

from lambdas.cis_scanner.src.handler import (
    handler,
    check_1_4_root_no_access_keys,
    check_1_5_root_mfa,
    check_1_10_iam_users_mfa,
    check_3_1_cloudtrail_enabled,
    check_3_3_cloudtrail_log_validation,
    check_4_x_unrestricted_ports,
)
from lambdas.shared.models import FindingStatus, Severity

REGION = "us-east-1"
TABLE_NAME = "cloudguard-findings-test"
ACCOUNT_ID = "123456789012"


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


def _make_sg_with_open_ssh(ec2_client):
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    sg = ec2_client.create_security_group(
        GroupName="open-ssh", Description="test", VpcId=vpc["Vpc"]["VpcId"]
    )
    ec2_client.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )
    return sg["GroupId"]


# --- CIS 1.4 ---

@mock_aws
def test_check_1_4_pass_no_root_keys():
    iam = boto3.client("iam", region_name=REGION)
    findings = check_1_4_root_no_access_keys(iam, REGION, ACCOUNT_ID)
    assert len(findings) == 1
    assert findings[0].status == FindingStatus.ACKNOWLEDGED
    assert findings[0].cis_check_id == "1.4"


# --- CIS 1.5 ---

@mock_aws
def test_check_1_5_root_mfa_disabled():
    iam = boto3.client("iam", region_name=REGION)
    # moto returns AccountMFAEnabled=0 by default
    findings = check_1_5_root_mfa(iam, REGION, ACCOUNT_ID)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].status == FindingStatus.DETECTED


# --- CIS 1.10 ---

@mock_aws
def test_check_1_10_user_with_console_no_mfa():
    iam = boto3.client("iam", region_name=REGION)
    iam.create_user(UserName="no-mfa-user")
    iam.create_login_profile(UserName="no-mfa-user", Password="Temp@12345!")

    findings = check_1_10_iam_users_mfa(iam, REGION, ACCOUNT_ID)
    assert len(findings) == 1
    assert findings[0].resource_id == "no-mfa-user"
    assert findings[0].cis_check_id == "1.10"


@mock_aws
def test_check_1_10_no_console_users_no_findings():
    iam = boto3.client("iam", region_name=REGION)
    iam.create_user(UserName="programmatic-only")
    # No login profile

    findings = check_1_10_iam_users_mfa(iam, REGION, ACCOUNT_ID)
    assert findings == []


# --- CIS 3.1 ---

@mock_aws
def test_check_3_1_no_trails():
    ct = boto3.client("cloudtrail", region_name=REGION)
    findings = check_3_1_cloudtrail_enabled(ct, REGION, ACCOUNT_ID)
    assert len(findings) == 1
    assert findings[0].finding_type == "CIS_3_1_CLOUDTRAIL_NOT_ENABLED"
    assert findings[0].severity == Severity.CRITICAL


@mock_aws
def test_check_3_1_trail_exists_and_logging():
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="ct-logs-bucket")
    ct = boto3.client("cloudtrail", region_name=REGION)
    ct.create_trail(Name="test-trail", S3BucketName="ct-logs-bucket")
    ct.start_logging(Name="test-trail")

    findings = check_3_1_cloudtrail_enabled(ct, REGION, ACCOUNT_ID)
    assert any(f.status == FindingStatus.ACKNOWLEDGED for f in findings)


# --- CIS 3.3 ---

@mock_aws
def test_check_3_3_validation_disabled():
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="ct-logs-bucket")
    ct = boto3.client("cloudtrail", region_name=REGION)
    ct.create_trail(
        Name="no-validation-trail",
        S3BucketName="ct-logs-bucket",
        EnableLogFileValidation=False,
    )
    findings = check_3_3_cloudtrail_log_validation(ct, REGION, ACCOUNT_ID)
    assert any(f.finding_type == "CIS_3_3_LOG_VALIDATION_DISABLED" for f in findings)


# --- CIS 4.x ---

@mock_aws
def test_check_4_x_open_ssh_detected():
    ec2 = boto3.client("ec2", region_name=REGION)
    group_id = _make_sg_with_open_ssh(ec2)

    findings = check_4_x_unrestricted_ports(ec2, REGION, ACCOUNT_ID)
    assert any(f.resource_id == group_id for f in findings)
    assert any(f.cis_check_id == "4.1" for f in findings)


@mock_aws
def test_check_4_x_clean_sg_no_findings():
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    ec2.create_security_group(
        GroupName="clean-sg", Description="test", VpcId=vpc["Vpc"]["VpcId"]
    )
    findings = check_4_x_unrestricted_ports(ec2, REGION, ACCOUNT_ID)
    assert findings == []


# --- Handler integration ---

@mock_aws
def test_handler_runs_all_checks_and_writes_findings():
    _make_table()
    result = handler({}, None)

    assert result["statusCode"] == 200
    assert "total_checks" in result
    assert "failed" in result
    assert "passed" in result
    assert result["total_checks"] > 0

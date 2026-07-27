"""
Tests for iam-remediator Lambda handler.
All AWS calls are moto-mocked — no live AWS required.
"""

import boto3
import pytest
from moto import mock_aws

from lambdas.iam_remediator.src.handler import (
    handler,
    _has_mfa,
    _has_login_profile,
    _disable_console_access,
    _is_root_event,
)

REGION = "us-east-1"
TABLE_NAME = "cloudguard-findings-test"


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


def _create_user(iam_client, username, with_console=True, with_mfa=False):
    iam_client.create_user(UserName=username)
    if with_console:
        iam_client.create_login_profile(UserName=username, Password="Temp@12345!", PasswordResetRequired=True)
    if with_mfa:
        # moto supports virtual MFA devices
        serial = iam_client.create_virtual_mfa_device(
            VirtualMFADeviceName=f"{username}-mfa"
        )["VirtualMFADevice"]["SerialNumber"]
        iam_client.enable_mfa_device(
            UserName=username,
            SerialNumber=serial,
            AuthenticationCode1="123456",
            AuthenticationCode2="789012",
        )


def _make_event(event_name, username, user_type="IAMUser"):
    return {
        "source": "aws.iam",
        "detail": {
            "eventName": event_name,
            "awsRegion": REGION,
            "userIdentity": {"type": user_type, "accountId": "123456789012"},
            "requestParameters": {"userName": username},
        },
    }


# --- Unit tests ---

@mock_aws
def test_has_mfa_false_when_no_device():
    iam = boto3.client("iam", region_name=REGION)
    iam.create_user(UserName="testuser")
    assert _has_mfa(iam, "testuser") is False


@mock_aws
def test_has_login_profile_true():
    iam = boto3.client("iam", region_name=REGION)
    _create_user(iam, "testuser", with_console=True)
    assert _has_login_profile(iam, "testuser") is True


@mock_aws
def test_has_login_profile_false():
    iam = boto3.client("iam", region_name=REGION)
    iam.create_user(UserName="testuser")
    assert _has_login_profile(iam, "testuser") is False


@mock_aws
def test_disable_console_access_removes_login_profile():
    iam = boto3.client("iam", region_name=REGION)
    _create_user(iam, "testuser", with_console=True)
    _disable_console_access(iam, "testuser")
    assert _has_login_profile(iam, "testuser") is False


def test_is_root_event_true():
    detail = {"userIdentity": {"type": "Root"}}
    assert _is_root_event(detail) is True


def test_is_root_event_false():
    detail = {"userIdentity": {"type": "IAMUser"}}
    assert _is_root_event(detail) is False


# --- Integration tests ---

@mock_aws
def test_handler_disables_console_access_when_no_mfa():
    iam = boto3.client("iam", region_name=REGION)
    _create_user(iam, "no-mfa-user", with_console=True, with_mfa=False)
    table = _make_table()

    result = handler(_make_event("CreateLoginProfile", "no-mfa-user"), None)

    assert result["action"] == "remediated"
    assert result["username"] == "no-mfa-user"

    # Console access must be gone
    assert _has_login_profile(iam, "no-mfa-user") is False

    # Finding must be recorded
    resp = table.scan()
    assert resp["Count"] == 1
    assert resp["Items"][0]["status"] == "REMEDIATED"
    assert resp["Items"][0]["service"] == "iam"


@mock_aws
def test_handler_leaves_user_with_mfa_alone():
    iam = boto3.client("iam", region_name=REGION)
    _create_user(iam, "mfa-user", with_console=True, with_mfa=True)
    _make_table()

    result = handler(_make_event("CreateLoginProfile", "mfa-user"), None)

    assert result["action"] == "clean"
    assert _has_login_profile(iam, "mfa-user") is True


@mock_aws
def test_handler_leaves_user_without_console_alone():
    iam = boto3.client("iam", region_name=REGION)
    _create_user(iam, "no-console-user", with_console=False)
    _make_table()

    result = handler(_make_event("CreateUser", "no-console-user"), None)

    assert result["action"] == "clean"


@mock_aws
def test_handler_flags_root_usage_no_remediation():
    _make_table()
    result = handler(_make_event("CreateLoginProfile", "root", user_type="Root"), None)

    assert result["action"] == "flagged_root_usage"


@mock_aws
def test_handler_skips_when_no_username():
    _make_table()
    event = {
        "source": "aws.iam",
        "detail": {
            "eventName": "CreateLoginProfile",
            "awsRegion": REGION,
            "userIdentity": {"type": "IAMUser", "accountId": "123456789012"},
            "requestParameters": {},
        },
    }
    result = handler(event, None)
    assert result["action"] == "skipped"

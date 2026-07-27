"""
Tests for s3-remediator Lambda handler.
All AWS calls are moto-mocked — no live AWS required.
"""

import boto3
import pytest
from moto import mock_aws

from lambdas.s3_remediator.src.handler import (
    handler,
    _is_public_access_blocked,
    _enable_public_access_block,
)

REGION = "us-east-1"
TABLE_NAME = "cloudguard-findings-test"
BUCKET = "test-bucket-cypher"


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


def _make_bucket(s3_client, public=False):
    s3_client.create_bucket(Bucket=BUCKET)
    if not public:
        s3_client.put_public_access_block(
            Bucket=BUCKET,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )


def _make_event(event_name):
    return {
        "source": "aws.s3",
        "detail": {
            "eventName": event_name,
            "awsRegion": REGION,
            "userIdentity": {"accountId": "123456789012"},
            "requestParameters": {"bucketName": BUCKET},
        },
    }


# --- Unit tests ---

@mock_aws
def test_is_public_access_blocked_when_enabled():
    s3 = boto3.client("s3", region_name=REGION)
    _make_bucket(s3, public=False)
    assert _is_public_access_blocked(s3, BUCKET) is True


@mock_aws
def test_is_public_access_blocked_when_no_config():
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket=BUCKET)
    assert _is_public_access_blocked(s3, BUCKET) is False


@mock_aws
def test_enable_public_access_block():
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket=BUCKET)
    _enable_public_access_block(s3, BUCKET)
    assert _is_public_access_blocked(s3, BUCKET) is True


# --- Integration tests ---

@mock_aws
def test_handler_remediates_deleted_public_access_block():
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket=BUCKET)  # no block config — simulates DeletePublicAccessBlock
    table = _make_table()

    result = handler(_make_event("DeletePublicAccessBlock"), None)

    assert result["action"] == "remediated"
    assert result["bucket"] == BUCKET

    # Verify block is now enabled
    assert _is_public_access_blocked(s3, BUCKET) is True

    # Verify finding written
    resp = table.scan()
    assert resp["Count"] == 1
    assert resp["Items"][0]["status"] == "REMEDIATED"
    assert resp["Items"][0]["severity"] == "CRITICAL"


@mock_aws
def test_handler_skips_when_already_blocked():
    s3 = boto3.client("s3", region_name=REGION)
    _make_bucket(s3, public=False)
    _make_table()

    result = handler(_make_event("DeletePublicAccessBlock"), None)

    assert result["action"] == "clean"


@mock_aws
def test_handler_flags_policy_change_no_auto_remediation():
    s3 = boto3.client("s3", region_name=REGION)
    _make_bucket(s3)
    table = _make_table()

    result = handler(_make_event("PutBucketPolicy"), None)

    assert result["action"] == "flagged"
    resp = table.scan()
    assert resp["Items"][0]["status"] == "NO_AUTO_REMEDIATION"


@mock_aws
def test_handler_flags_acl_change_no_auto_remediation():
    s3 = boto3.client("s3", region_name=REGION)
    _make_bucket(s3)
    table = _make_table()

    result = handler(_make_event("PutBucketAcl"), None)

    assert result["action"] == "flagged"


@mock_aws
def test_handler_skips_when_no_bucket_name():
    _make_table()
    event = {
        "source": "aws.s3",
        "detail": {
            "eventName": "DeletePublicAccessBlock",
            "awsRegion": REGION,
            "userIdentity": {"accountId": "123456789012"},
            "requestParameters": {},
        },
    }
    result = handler(event, None)
    assert result["action"] == "skipped"

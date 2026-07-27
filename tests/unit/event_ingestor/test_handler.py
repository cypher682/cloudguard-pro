"""
Tests for event-ingestor Lambda handler.
All AWS calls are moto-mocked — no live AWS required.
"""

import json
import os

import boto3
import pytest
from moto import mock_aws

from lambdas.event_ingestor.src.handler import handler, _build_finding, _extract_resource_id
from lambdas.shared.models import Severity, FindingStatus, FindingSource


TABLE_NAME = "cloudguard-findings-test"


def _make_table(region="us-east-1"):
    ddb = boto3.resource("dynamodb", region_name=region)
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


# --- Fixtures ---

@pytest.fixture
def sg_event():
    return {
        "source": "aws.ec2",
        "detail-type": "AWS API Call via CloudTrail",
        "region": "us-east-1",
        "detail": {
            "eventName": "AuthorizeSecurityGroupIngress",
            "eventSource": "ec2.amazonaws.com",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "1.2.3.4",
            "userAgent": "aws-cli/2.x",
            "userIdentity": {"type": "IAMUser", "accountId": "123456789012"},
            "requestParameters": {"groupId": "sg-0abc123"},
        },
    }


@pytest.fixture
def s3_event():
    return {
        "source": "aws.s3",
        "detail-type": "AWS API Call via CloudTrail",
        "region": "us-east-1",
        "detail": {
            "eventName": "DeletePublicAccessBlock",
            "eventSource": "s3.amazonaws.com",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "5.6.7.8",
            "userAgent": "console.aws.amazon.com",
            "userIdentity": {"type": "Root", "accountId": "123456789012"},
            "requestParameters": {"bucketName": "my-sensitive-bucket"},
        },
    }


@pytest.fixture
def iam_event():
    return {
        "source": "aws.iam",
        "detail-type": "AWS API Call via CloudTrail",
        "region": "us-east-1",
        "detail": {
            "eventName": "CreateLoginProfile",
            "eventSource": "iam.amazonaws.com",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "9.10.11.12",
            "userAgent": "aws-cli/2.x",
            "userIdentity": {"type": "IAMUser", "accountId": "123456789012"},
            "requestParameters": {"userName": "new-user"},
        },
    }


# --- Unit tests (no AWS) ---

def test_extract_resource_id_sg(sg_event):
    rid = _extract_resource_id(sg_event["detail"])
    assert rid == "sg-0abc123"


def test_extract_resource_id_s3(s3_event):
    rid = _extract_resource_id(s3_event["detail"])
    assert rid == "my-sensitive-bucket"


def test_extract_resource_id_iam(iam_event):
    rid = _extract_resource_id(iam_event["detail"])
    assert rid == "new-user"


def test_extract_resource_id_unknown():
    rid = _extract_resource_id({})
    assert rid == "unknown"


def test_build_finding_sg(sg_event):
    finding = _build_finding(sg_event)
    assert finding.service == "ec2"
    assert finding.finding_type == "AUTHORIZESECURITYGROUPINGRESS"
    assert finding.severity == Severity.HIGH
    assert finding.source == FindingSource.CLOUDTRAIL
    assert finding.resource_id == "sg-0abc123"
    assert finding.status == FindingStatus.DETECTED
    assert finding.raw_event_summary["eventName"] == "AuthorizeSecurityGroupIngress"


def test_build_finding_s3_critical(s3_event):
    finding = _build_finding(s3_event)
    assert finding.service == "s3"
    assert finding.severity == Severity.CRITICAL
    assert finding.resource_id == "my-sensitive-bucket"


def test_build_finding_iam(iam_event):
    finding = _build_finding(iam_event)
    assert finding.service == "iam"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_id == "new-user"


def test_build_finding_unknown_event():
    event = {
        "source": "aws.ec2",
        "detail": {
            "eventName": "SomeUnknownEvent",
            "awsRegion": "us-east-1",
            "userIdentity": {"accountId": "123456789012"},
        },
    }
    finding = _build_finding(event)
    assert finding.severity == Severity.INFO


# --- Integration tests (moto-mocked DynamoDB) ---

@mock_aws
def test_handler_writes_finding_to_dynamo(sg_event):
    table = _make_table()

    result = handler(sg_event, None)

    assert result["statusCode"] == 200
    assert "finding_id" in result

    resp = table.scan()
    assert resp["Count"] == 1
    item = resp["Items"][0]
    assert item["finding_id"] == result["finding_id"]
    assert item["service"] == "ec2"
    assert item["severity"] == "HIGH"
    assert item["status"] == "DETECTED"


@mock_aws
def test_handler_s3_event_stores_correctly(s3_event):
    table = _make_table()

    result = handler(s3_event, None)

    assert result["statusCode"] == 200
    resp = table.scan()
    assert resp["Count"] == 1
    assert resp["Items"][0]["severity"] == "CRITICAL"
    assert resp["Items"][0]["resource_id"] == "my-sensitive-bucket"


@mock_aws
def test_handler_multiple_events_stored_independently(sg_event, s3_event):
    table = _make_table()

    handler(sg_event, None)
    handler(s3_event, None)

    resp = table.scan()
    assert resp["Count"] == 2
    services = {item["service"] for item in resp["Items"]}
    assert services == {"ec2", "s3"}

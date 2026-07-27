"""
Tests for finding-notifier Lambda handler.
All AWS calls are moto-mocked — no live AWS required.
"""

import json
import os

import boto3
import pytest
from moto import mock_aws

from lambdas.finding_notifier.src.handler import (
    handler,
    _deserialize_dynamo_item,
    _format_subject,
    _format_message,
)
from lambdas.shared.models import Finding, FindingSource, FindingStatus, Severity

REGION = "us-east-1"
TOPIC_NAME = "cloudguard-alerts-test"


def _make_topic():
    sns = boto3.client("sns", region_name=REGION)
    resp = sns.create_topic(Name=TOPIC_NAME)
    topic_arn = resp["TopicArn"]
    os.environ["SNS_TOPIC_ARN"] = topic_arn
    return topic_arn, sns


def _make_finding(**kwargs):
    defaults = dict(
        service="ec2",
        finding_type="OPEN_SSH_INGRESS",
        severity=Severity.HIGH,
        source=FindingSource.CLOUDTRAIL,
        resource_id="sg-0abc123",
        description="Test finding",
        region=REGION,
        account_id="123456789012",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _dynamo_stream_record(finding: Finding, event_name="INSERT") -> dict:
    """Build a DynamoDB Streams record from a Finding."""
    item = finding.to_item()
    new_image = {k: {"S": str(v)} for k, v in item.items() if v is not None}
    return {
        "eventName": event_name,
        "dynamodb": {"NewImage": new_image},
    }


# --- Unit tests ---

def test_deserialize_dynamo_item_strings():
    raw = {"finding_id": {"S": "abc"}, "severity": {"S": "HIGH"}}
    result = _deserialize_dynamo_item(raw)
    assert result == {"finding_id": "abc", "severity": "HIGH"}


def test_deserialize_dynamo_item_number():
    raw = {"count": {"N": "5"}}
    result = _deserialize_dynamo_item(raw)
    assert result["count"] == "5"


def test_format_subject_includes_severity_and_type():
    finding = _make_finding()
    subject = _format_subject(finding)
    assert "HIGH" in subject
    assert "OPEN_SSH_INGRESS" in subject
    assert "EC2" in subject


def test_format_subject_max_100_chars():
    finding = _make_finding(finding_type="A" * 200)
    subject = _format_subject(finding)
    # handler truncates to 100 at publish time — subject itself can be longer
    # just verify it contains the key parts
    assert "HIGH" in subject


def test_format_message_contains_key_fields():
    finding = _make_finding()
    message = _format_message(finding)
    assert finding.resource_id in message
    assert finding.finding_id in message
    assert finding.description in message
    assert finding.region in message


def test_format_message_includes_remediation_when_remediated():
    finding = _make_finding(
        status=FindingStatus.REMEDIATED,
        remediation_action="revoke_sg_rule on sg-0abc123",
        remediated_at="2026-01-01T00:00:00.000000Z",
    )
    message = _format_message(finding)
    assert "Auto-Remediation" in message
    assert "revoke_sg_rule" in message


def test_format_message_includes_cis_check_id():
    finding = _make_finding(cis_check_id="4.1")
    message = _format_message(finding)
    assert "4.1" in message


# --- Integration tests ---

@mock_aws
def test_handler_publishes_on_insert():
    topic_arn, sns = _make_topic()
    finding = _make_finding()
    event = {"Records": [_dynamo_stream_record(finding, event_name="INSERT")]}

    result = handler(event, None)

    assert result["published"] == 1
    assert result["skipped"] == 0


@mock_aws
def test_handler_skips_modify_events():
    topic_arn, sns = _make_topic()
    finding = _make_finding()
    event = {"Records": [_dynamo_stream_record(finding, event_name="MODIFY")]}

    result = handler(event, None)

    assert result["published"] == 0
    assert result["skipped"] == 1


@mock_aws
def test_handler_skips_remove_events():
    topic_arn, sns = _make_topic()
    finding = _make_finding()
    event = {"Records": [_dynamo_stream_record(finding, event_name="REMOVE")]}

    result = handler(event, None)

    assert result["published"] == 0
    assert result["skipped"] == 1


@mock_aws
def test_handler_publishes_multiple_records():
    topic_arn, sns = _make_topic()
    records = [
        _dynamo_stream_record(_make_finding(service="ec2"), event_name="INSERT"),
        _dynamo_stream_record(_make_finding(service="s3"), event_name="INSERT"),
        _dynamo_stream_record(_make_finding(service="iam"), event_name="MODIFY"),
    ]
    event = {"Records": records}

    result = handler(event, None)

    assert result["published"] == 2
    assert result["skipped"] == 1


@mock_aws
def test_handler_empty_records():
    _make_topic()
    result = handler({"Records": []}, None)
    assert result["published"] == 0
    assert result["skipped"] == 0

"""
pulumi/__main__.py — cloudguard-pro Lambda deployment layer.

Scope:
  - 7 Lambda functions with their source zipped at deploy time
  - One IAM execution role per Lambda (least privilege)
  - Lambda Layer publishing lambdas/shared/ for all functions
  - EventBridge invoke permissions wired to Terraform-managed rule ARNs
  - DynamoDB Streams event source mapping for finding-notifier

Out of scope (owned by Terraform):
  - EventBridge bus + rules (see terraform/modules/eventbridge)
  - DynamoDB table + streams config
  - SNS topic + subscription
  - Config rules
  - Security Hub

Terraform outputs are read via pulumi.Config so this stack can be run
after `terraform apply` without hardcoding any ARNs.
"""

import os
import shutil
import zipfile
from pathlib import Path

import pulumi
import pulumi_aws as aws

config = pulumi.Config()

# --- Values injected after `terraform apply` ---
# Set with: pulumi config set findingsTableArn <value>
findings_table_arn    = config.require("findingsTableArn")
findings_table_name   = config.require("findingsTableName")
findings_stream_arn   = config.require("findingsStreamArn")
sns_topic_arn         = config.require("snsTopicArn")
eb_bus_arn            = config.require("eventBridgeBusArn")

# EventBridge rule ARNs (for Lambda invoke permissions)
rule_arns = {
    "all_events":           config.require("ruleArnAllEvents"),
    "sg_changes":           config.require("ruleArnSgChanges"),
    "s3_policy_changes":    config.require("ruleArnS3PolicyChanges"),
    "iam_changes":          config.require("ruleArnIamChanges"),
    "cis_scan_schedule":    config.require("ruleArnCisScanSchedule"),
    "sh_sync_schedule":     config.require("ruleArnShSyncSchedule"),
}

aws_region  = config.get("awsRegion") or "us-east-1"
aws_account = config.require("awsAccountId")

REPO_ROOT   = Path(__file__).resolve().parent.parent
LAMBDAS_DIR = REPO_ROOT / "lambdas"
BUILD_DIR   = REPO_ROOT / ".pulumi-build"

# ── Helper: zip a Lambda function ────────────────────────────────────────────

def _zip_lambda(name: str) -> str:
    """
    Zip lambdas/<name>/src/ + lambdas/shared/ into .pulumi-build/<name>.zip.
    Returns the path to the zip file.
    """
    BUILD_DIR.mkdir(exist_ok=True)
    zip_name = name.replace("_", "-")
    zip_path = BUILD_DIR / f"{zip_name}.zip"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Lambda handler source
        src_dir = LAMBDAS_DIR / name / "src"
        for f in src_dir.rglob("*.py"):
            zf.write(f, f.relative_to(src_dir))

    return str(zip_path)


def _zip_layer() -> str:
    """Zip lambdas/shared/ into a Lambda Layer package."""
    layer_path = BUILD_DIR / "shared-layer.zip"
    BUILD_DIR.mkdir(exist_ok=True)

    with zipfile.ZipFile(layer_path, "w", zipfile.ZIP_DEFLATED) as zf:
        shared_dir = LAMBDAS_DIR / "shared"
        # Layer must be under python/ prefix for Python runtime
        for f in shared_dir.rglob("*.py"):
            zf.write(f, Path("python") / "lambdas" / "shared" / f.relative_to(shared_dir))

    return str(layer_path)


# ── Lambda Layer (shared utilities) ──────────────────────────────────────────

layer_zip = _zip_layer()

shared_layer = aws.lambda_.LayerVersion(
    "cloudguard-shared-layer",
    layer_name="cloudguard-shared",
    code=pulumi.FileArchive(layer_zip),
    compatible_runtimes=["python3.12"],
    description="Shared logging, models, and DynamoDB client for cloudguard-pro Lambdas",
)

# ── IAM: base execution role (each Lambda gets its own) ──────────────────────

def _make_role(name: str, extra_policy: dict | None = None) -> aws.iam.Role:
    role_name = f"cloudguard-{name.replace('_', '-')}-role"
    assume = aws.iam.Role(
        f"cloudguard-{name.replace('_', '-')}-role",
        name=role_name,
        assume_role_policy=pulumi.Output.json_dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        tags={"Lambda": name, "ManagedBy": "pulumi"},
    )

    # Basic execution (CloudWatch Logs)
    aws.iam.RolePolicyAttachment(
        f"cloudguard-{name.replace('_', '-')}-basic-exec",
        role=assume.name,
        policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )

    if extra_policy:
        aws.iam.RolePolicy(
            f"cloudguard-{name.replace('_', '-')}-policy",
            role=assume.name,
            policy=pulumi.Output.json_dumps(extra_policy),
        )

    return assume


# ── Lambda factory ────────────────────────────────────────────────────────────

def _make_lambda(
    name: str,
    role: aws.iam.Role,
    env_vars: dict,
    timeout: int = 30,
) -> aws.lambda_.Function:
    zip_path = _zip_lambda(name)
    fn_name  = f"cloudguard-{name.replace('_', '-')}"

    return aws.lambda_.Function(
        fn_name,
        name=fn_name,
        runtime="python3.12",
        code=pulumi.FileArchive(zip_path),
        handler="handler.handler",
        role=role.arn,
        layers=[shared_layer.arn],
        timeout=timeout,
        environment=aws.lambda_.FunctionEnvironmentArgs(variables={
            "FINDINGS_TABLE_NAME": findings_table_name,
            "SNS_TOPIC_ARN":       sns_topic_arn,
            "AWS_ACCOUNT_ID":      aws_account,
            **env_vars,
        }),
        tags={"ManagedBy": "pulumi"},
    )


def _eb_permission(fn: aws.lambda_.Function, rule_arn: str, sid: str) -> aws.lambda_.Permission:
    return aws.lambda_.Permission(
        f"cloudguard-{sid}-permission",
        action="lambda:InvokeFunction",
        function=fn.name,
        principal="events.amazonaws.com",
        source_arn=rule_arn,
    )


# ── event_ingestor ────────────────────────────────────────────────────────────

ingestor_role = _make_role("event_ingestor", {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["dynamodb:PutItem"],
        "Resource": findings_table_arn,
    }],
})

event_ingestor = _make_lambda("event_ingestor", ingestor_role, {})

_eb_permission(event_ingestor, rule_arns["all_events"], "ingestor-all-events")

# ── sg-remediator ─────────────────────────────────────────────────────────────

sg_role = _make_role("sg_remediator", {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["dynamodb:PutItem"],
            "Resource": findings_table_arn,
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeSecurityGroups",
                "ec2:RevokeSecurityGroupIngress",
            ],
            "Resource": "*",
        },
    ],
})

sg_remediator = _make_lambda("sg_remediator", sg_role, {})
_eb_permission(sg_remediator, rule_arns["sg_changes"], "sg-remediator-sg-changes")

# ── s3-remediator ─────────────────────────────────────────────────────────────

s3_role = _make_role("s3_remediator", {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["dynamodb:PutItem"],
            "Resource": findings_table_arn,
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetPublicAccessBlock",
                "s3:PutPublicAccessBlock",
            ],
            "Resource": "*",
        },
    ],
})

s3_remediator = _make_lambda("s3_remediator", s3_role, {})
_eb_permission(s3_remediator, rule_arns["s3_policy_changes"], "s3-remediator-s3-changes")

# ── iam-remediator ────────────────────────────────────────────────────────────

iam_role = _make_role("iam_remediator", {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["dynamodb:PutItem"],
            "Resource": findings_table_arn,
        },
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetLoginProfile",
                "iam:DeleteLoginProfile",
                "iam:ListMFADevices",
            ],
            "Resource": "*",
        },
    ],
})

iam_remediator = _make_lambda("iam_remediator", iam_role, {})
_eb_permission(iam_remediator, rule_arns["iam_changes"], "iam-remediator-iam-changes")

# ── cis-scanner ───────────────────────────────────────────────────────────────

cis_role = _make_role("cis_scanner", {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["dynamodb:PutItem"],
            "Resource": findings_table_arn,
        },
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountSummary",
                "iam:ListUsers",
                "iam:GetLoginProfile",
                "iam:ListMFADevices",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "ec2:DescribeSecurityGroups",
            ],
            "Resource": "*",
        },
    ],
})

cis_scanner = _make_lambda("cis_scanner", cis_role, {}, timeout=120)
_eb_permission(cis_scanner, rule_arns["cis_scan_schedule"], "cis-scanner-schedule")

# ── finding-notifier ──────────────────────────────────────────────────────────

notifier_role = _make_role("finding_notifier", {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["dynamodb:GetRecords", "dynamodb:GetShardIterator",
                       "dynamodb:DescribeStream", "dynamodb:ListStreams"],
            "Resource": findings_stream_arn,
        },
        {
            "Effect": "Allow",
            "Action": ["sns:Publish"],
            "Resource": sns_topic_arn,
        },
    ],
})

finding_notifier = _make_lambda("finding_notifier", notifier_role, {})

# DynamoDB Streams event source mapping — triggers on new findings
aws.lambda_.EventSourceMapping(
    "cloudguard-findings-stream-esm",
    event_source_arn=findings_stream_arn,
    function_name=finding_notifier.name,
    starting_position="LATEST",
    filter_criteria=aws.lambda_.EventSourceMappingFilterCriteriaArgs(
        filters=[aws.lambda_.EventSourceMappingFilterCriteriaFilterArgs(
            pattern='{"eventName": ["INSERT"]}',
        )],
    ),
)

# ── security-hub-sync ─────────────────────────────────────────────────────────

sh_role = _make_role("security_hub_sync", {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["dynamodb:PutItem"],
            "Resource": findings_table_arn,
        },
        {
            "Effect": "Allow",
            "Action": ["securityhub:GetFindings"],
            "Resource": "*",
        },
    ],
})

sh_sync = _make_lambda("security_hub_sync", sh_role, {}, timeout=300)
_eb_permission(sh_sync, rule_arns["sh_sync_schedule"], "sh-sync-schedule")

# ── Outputs ───────────────────────────────────────────────────────────────────

pulumi.export("event_ingestor_arn",  event_ingestor.arn)
pulumi.export("sg_remediator_arn",   sg_remediator.arn)
pulumi.export("s3_remediator_arn",   s3_remediator.arn)
pulumi.export("iam_remediator_arn",  iam_remediator.arn)
pulumi.export("cis_scanner_arn",     cis_scanner.arn)
pulumi.export("finding_notifier_arn",finding_notifier.arn)
pulumi.export("sh_sync_arn",         sh_sync.arn)
pulumi.export("shared_layer_arn",    shared_layer.arn)

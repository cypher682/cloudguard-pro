# D3 cloudguard-pro — Pre-Sprint Checklist

Complete every item on this list before running `terraform apply`.
The sprint should be a single session: apply → trigger → verify → evidence → destroy.

---

## Phase A Completion (Local Build)

- [ ] All 70 tests passing (`python -m pytest tests/ -q`)
- [ ] Coverage >= 80% (currently 87%)
- [ ] `terraform fmt -recursive terraform/` runs clean
- [ ] `terraform validate` runs clean (with `-backend=false`)
- [ ] `ruff check lambdas/ tests/` clean
- [ ] `bandit -r lambdas/` no HIGH severity issues
- [ ] All Lambda handlers reviewed — no hardcoded account IDs or ARNs

---

## AWS Account Readiness

- [ ] AWS CLI configured: `aws sts get-caller-identity` returns your account
- [ ] IAM user/role has permissions for:
  - EC2 (describe, authorize, revoke security groups)
  - S3 (create bucket, put policy, public access block)
  - IAM (create user, login profile, MFA devices)
  - DynamoDB (create table, put/get/update item, streams)
  - SNS (create topic, publish, subscribe)
  - EventBridge (create bus, rules, targets)
  - Lambda (create function, invoke, add permission, event source mapping)
  - CloudTrail (describe trails, get trail status)
  - Config (recorder, delivery channel, config rules)
  - Security Hub (enable, get findings)
  - CloudWatch Logs (create log group, put log events)

---

## Sprint Sequence

### Bootstrap (once)

```bash
cd terraform/modules/state-backend
terraform init
terraform apply -var="bucket_name=cloudguard-pro-tfstate-$(aws sts get-caller-identity --query Account --output text)"
# Note the bucket_name and lock_table_name outputs
# Update terraform/main.tf backend block with real values
```

### Terraform apply

```bash
cd terraform
terraform init   # migrates to S3 backend
terraform plan -var="alert_email=YOUR_EMAIL"
terraform apply -var="alert_email=YOUR_EMAIL"
# Copy all outputs — needed for Pulumi config
```

### Pulumi config + up

```bash
cd pulumi
cp Pulumi.dev.yaml.example Pulumi.dev.yaml
# Fill in all values from terraform outputs
pulumi stack init dev
pulumi up --yes --stack dev
# Note all Lambda ARNs from outputs
```

### Second terraform apply (wire Lambda targets)

```bash
cd terraform
# Add Lambda ARNs to terraform.tfvars using Pulumi outputs
terraform apply -var-file=terraform.tfvars
```

---

## Evidence to Collect (all in docs/evidence/)

- [ ] `terraform apply` output (terminal screenshot)
- [ ] `pulumi up` output (terminal screenshot)
- [ ] SNS subscription confirmation email (screenshot of inbox)
- [ ] DynamoDB table in AWS console (screenshot — empty, then after tests)
- [ ] **Trigger 1 — Open SSH SG:**
  ```bash
  # Create SG with open SSH
  aws ec2 create-security-group --group-name test-open-ssh --description "test"
  aws ec2 authorize-security-group-ingress --group-id <sg-id> \
    --protocol tcp --port 22 --cidr 0.0.0.0/0
  # Wait ~30s, then verify sg-remediator revoked it:
  aws ec2 describe-security-groups --group-ids <sg-id>
  ```
  Screenshot: SG before (showing 0.0.0.0/0 rule) + after (rule gone)
- [ ] **Trigger 2 — S3 public access:**
  ```bash
  aws s3api create-bucket --bucket cloudguard-test-$(date +%s)
  aws s3api delete-public-access-block --bucket <bucket-name>
  # Wait ~30s, then verify s3-remediator re-enabled block:
  aws s3api get-public-access-block --bucket <bucket-name>
  ```
  Screenshot: public access block before (absent) + after (all four flags true)
- [ ] **Trigger 3 — IAM user no MFA:**
  ```bash
  aws iam create-user --user-name test-no-mfa-user
  aws iam create-login-profile --user-name test-no-mfa-user --password Temp@12345!
  # Wait ~30s, then verify iam-remediator disabled console access:
  aws iam get-login-profile --user-name test-no-mfa-user  # should 404
  ```
  Screenshot: before (login profile exists) + after (NoSuchEntity error)
- [ ] DynamoDB findings table — screenshot showing all three findings REMEDIATED
- [ ] SNS email notification received (screenshot)
- [ ] CloudWatch Logs for each Lambda invocation (screenshot)
- [ ] CIS scanner output: `aws lambda invoke --function-name cloudguard-cis-scanner out.json && cat out.json`
- [ ] Security Hub findings page (screenshot)
- [ ] `terraform destroy` output (screenshot — confirms full teardown)

---

## Teardown (immediately after evidence collected)

```bash
# Destroy Lambda layer first (Pulumi)
cd pulumi && pulumi destroy --yes --stack dev

# Destroy all infra (Terraform)
cd ../terraform && terraform destroy -var="alert_email=YOUR_EMAIL"

# Clean up test resources manually if not caught by destroy:
aws ec2 delete-security-group --group-id <sg-id>
aws s3 rb s3://<bucket-name> --force
aws iam delete-user --user-name test-no-mfa-user

# Empty and delete state bucket (optional — it's cheap but confirm sprint is done first)
aws s3 rm s3://<tfstate-bucket> --recursive
aws s3 rb s3://<tfstate-bucket>
```

---

## Post-Sprint

- [ ] All evidence screenshots in `docs/evidence/`
- [ ] Architecture diagram added to `docs/architecture.png`
- [ ] `docs/iac-comparison.md` written
- [ ] README updated with real evidence links
- [ ] Content drafts (Dev.to, LinkedIn, X)

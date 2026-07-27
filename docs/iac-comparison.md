# IaC Comparison: Terraform vs Pulumi in cloudguard-pro

## Why both tools in one project?

This project intentionally uses two IaC tools to provision different
parts of the same system. This documents the decision rationale and
the practical tradeoffs encountered.

---

## Split of responsibility

| Layer | Tool | Resources |
|---|---|---|
| Infrastructure | Terraform | EventBridge bus + rules, DynamoDB, SNS, Config rules, Security Hub |
| Compute | Pulumi | Lambda functions, IAM execution roles, Lambda Layer, event source mappings |

---

## Why Terraform for infrastructure?

**State is stable.** The EventBridge rules, DynamoDB table, and SNS
topic change rarely. Terraform's declarative plan/apply cycle is ideal
for long-lived, low-churn infrastructure where you want to see exactly
what will change before applying.

**Team-friendly.** HCL is readable by anyone on an ops team without
knowing Python. For resources that multiple people need to reason about
(networking, IAM foundations, data stores), the lowest common
denominator language wins.

**Mature provider coverage.** The AWS Terraform provider has broader
coverage and faster support for new AWS features than pulumi-aws at
the time of writing.

**Remote state locking.** Terraform's S3 + DynamoDB state locking is
battle-tested for team environments. Pulumi Cloud provides equivalent
functionality but adds a SaaS dependency for what Terraform can do with
resources you already own.

---

## Why Pulumi for Lambda?

**Dynamic packaging.** Lambda deployment requires zipping source code
at deploy time, computing file paths, and conditionally including
dependencies. In HCL this requires `null_resource` + local-exec hacks
or a separate packaging tool (Serverless Framework, SAM). In Pulumi's
Python, this is just Python: `zipfile.ZipFile`, `pathlib.Path`, done.

**Familiar language for Lambda authors.** The people writing Python
Lambda functions can also read and modify the Pulumi deployment code.
No context switch to a different language for "how does this get
deployed?"

**Programmatic IAM.** Each Lambda needs a least-privilege IAM role.
Generating seven near-identical roles with slight policy differences
is tedious and error-prone in HCL. In Pulumi, `_make_role()` is a
reusable Python function.

---

## Where the tools share a boundary

Terraform owns the EventBridge rules. Pulumi owns the Lambda functions.
Lambda invoke permissions (allowing EventBridge to trigger a Lambda)
are created by Pulumi because they reference both:
- The Lambda ARN (Pulumi output)
- The EventBridge rule ARN (Terraform output, injected via `pulumi config set`)

This cross-tool dependency is handled explicitly in `pulumi/Pulumi.dev.yaml`
where Terraform outputs are set as Pulumi stack config values.

At sprint time the sequence is:
1. `terraform apply` → collect outputs
2. Set outputs as Pulumi config values
3. `pulumi up` → Lambda functions created, permissions wired
4. Second `terraform apply` → EventBridge targets updated with Lambda ARNs

---

## When would I choose Pulumi over Terraform entirely?

- Projects where infrastructure is generated dynamically (e.g. one
  DynamoDB table per tenant, N Lambda functions from a config file)
- Teams where everyone writes Python and HCL is a barrier
- Projects that use Pulumi Automation API for programmatic deployments
  (e.g. a CLI that provisions infrastructure on demand)

## When would I choose Terraform over Pulumi entirely?

- Large team projects where IaC readability across disciplines matters
- Projects already using Terraform Cloud or Atlantis for GitOps workflows
- When the AWS provider feature gap between the two tools is relevant
  to what you're building

---

## Honest assessment

For a project like cloudguard-pro, Terraform alone with a packaging
script (`scripts/package-lambdas.sh`) would be simpler operationally —
one tool, one state file, one plan. The dual-tool approach here is
intentional for portfolio signal: it demonstrates the ability to use
both tools and reason about where each fits, rather than defaulting to
one for everything.

# Warden Terraform — cost guardrail and optional registry

Warden is designed to run entirely on free/open-source tooling at **£0**. This module does **not**
provision any compute. Its job is the opposite: a hard **cost tripwire** so that if anything ever
starts to cost money, you find out immediately rather than on the monthly bill.

It creates:

- **A monthly AWS Budget** (`budget_limit_usd`, default **$1**) with alerts at 80% actual and 100%
  forecasted spend.
- **An optional CloudWatch billing alarm** on total estimated charges, wired to an SNS email topic.
- **Optional ECR repositories** for the three Warden images, with a lifecycle policy that keeps
  only the five most recent tags (storage cost only).

## Use

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars   # set alert_email
terraform init
terraform plan
terraform apply
```

To create only the budget (no registry, no alarm):

```bash
terraform apply -var create_ecr=false -var create_billing_alarm=false
```

## Notes

- Budgets and billing metrics are only available in `us-east-1`; the module pins a second provider
  alias there automatically.
- A billing alarm requires that **"Receive Billing Alerts"** is enabled in the AWS Billing console
  (a one-time account setting Terraform cannot toggle).
- `terraform validate`/`plan` were not run in the build sandbox (no AWS credentials or provider
  download). Run them locally before `apply`.

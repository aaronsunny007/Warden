variable "region" {
  description = "AWS region for the (minimal, storage-only) resources."
  type        = string
  default     = "eu-west-2"
}

variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "warden"
}

variable "budget_limit_usd" {
  description = <<-EOT
    Monthly cost ceiling, in USD. Warden is designed to run at £0; this is a hard tripwire, not
    a spending plan. The default of 1 fires alerts the moment anything starts to cost money.
  EOT
  type        = number
  default     = 1
}

variable "alert_email" {
  description = "Email address for budget and billing alerts. Leave empty to skip notifications."
  type        = string
  default     = ""
}

variable "create_ecr" {
  description = "Create ECR repositories for the Warden images (storage cost only; lifecycle-pruned)."
  type        = bool
  default     = true
}

variable "create_billing_alarm" {
  description = "Also create a CloudWatch EstimatedCharges alarm (needs an SNS email subscription)."
  type        = bool
  default     = true
}

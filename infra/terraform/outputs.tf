output "budget_name" {
  description = "The monthly cost budget acting as the £0 tripwire."
  value       = aws_budgets_budget.monthly.name
}

output "ecr_repository_urls" {
  description = "Push targets for the Warden images (empty when create_ecr = false)."
  value       = { for k, r in aws_ecr_repository.warden : k => r.repository_url }
}

output "billing_alarm" {
  description = "Name of the CloudWatch estimated-charges alarm, if created."
  value       = try(aws_cloudwatch_metric_alarm.estimated_charges[0].alarm_name, null)
}

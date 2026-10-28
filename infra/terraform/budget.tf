# The cost guardrail. Warden's whole design target is £0; this makes "it started costing money"
# an alarm, not a surprise on the monthly bill.

locals {
  has_email = var.alert_email != ""
}

# A monthly cost budget with alerts at 80% actual and 100% forecasted spend.
resource "aws_budgets_budget" "monthly" {
  name         = "${var.name_prefix}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = local.has_email ? [80, 100] : []
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = notification.value >= 100 ? "FORECASTED" : "ACTUAL"
      subscriber_email_addresses = [var.alert_email]
    }
  }
}

# Optional: a CloudWatch billing alarm on total estimated charges (us-east-1 only).
resource "aws_sns_topic" "billing" {
  count    = var.create_billing_alarm && local.has_email ? 1 : 0
  provider = aws.us_east_1
  name     = "${var.name_prefix}-billing-alerts"
}

resource "aws_sns_topic_subscription" "billing_email" {
  count     = var.create_billing_alarm && local.has_email ? 1 : 0
  provider  = aws.us_east_1
  topic_arn = aws_sns_topic.billing[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_metric_alarm" "estimated_charges" {
  count               = var.create_billing_alarm && local.has_email ? 1 : 0
  provider            = aws.us_east_1
  alarm_name          = "${var.name_prefix}-estimated-charges"
  alarm_description   = "Total estimated AWS charges exceeded the Warden lab ceiling."
  namespace           = "AWS/Billing"
  metric_name         = "EstimatedCharges"
  dimensions          = { Currency = "USD" }
  statistic           = "Maximum"
  period              = 21600 # 6h (billing metrics update a few times a day)
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.budget_limit_usd
  alarm_actions       = [aws_sns_topic.billing[0].arn]
  treat_missing_data  = "notBreaching"
}

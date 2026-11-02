# Phase 3, managed detections and alerting.
#
# GuardDuty adds managed threat detection over CloudTrail, DNS and S3 (30-day free
# trial per account per Region). Its findings are routed through EventBridge to an
# SNS topic, so a finding reaches an inbox without anyone polling a console.

resource "aws_guardduty_detector" "main" {
  enable = true
}

# Email endpoint for alerts. No default, and passed with -var at apply time, so a
# personal address is never committed to the repository. With it unset, the topic
# and routing still deploy; only the email subscription is skipped.
variable "alert_email" {
  description = "Email address subscribed to the security alerts SNS topic."
  type        = string
  default     = ""
}

resource "aws_sns_topic" "alerts" {
  name = "cloud-iam-lab-security-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Let EventBridge publish to the topic.
data "aws_iam_policy_document" "alerts_topic" {
  statement {
    sid       = "AllowEventBridgePublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts_topic.json
}

# GuardDuty publishes findings to the default event bus as "GuardDuty Finding"
# events. This rule forwards them to the alerts topic.
resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "cloud-iam-lab-guardduty-findings"
  description = "Route GuardDuty findings to the security alerts topic."
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "guardduty_to_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "security-alerts"
  arn       = aws_sns_topic.alerts.arn
}

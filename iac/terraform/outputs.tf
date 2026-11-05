output "bucket_name" {
  description = "The data bucket name."
  value       = aws_s3_bucket.data.id
}

output "bucket_arn" {
  description = "The data bucket ARN."
  value       = aws_s3_bucket.data.arn
}

output "kms_key_arn" {
  description = "The customer-managed key ARN."
  value       = aws_kms_key.data.arn
}

output "s3_vpc_endpoint_id" {
  description = "The S3 gateway VPC endpoint ID (used by the enforce_vpce guardrail)."
  value       = aws_vpc_endpoint.s3.id
}

output "log_bucket_name" {
  description = "The CloudTrail log bucket name."
  value       = aws_s3_bucket.logs.id
}

output "trail_arn" {
  description = "The CloudTrail trail ARN."
  value       = aws_cloudtrail.main.arn
}

output "guardduty_detector_id" {
  description = "The GuardDuty detector ID."
  value       = aws_guardduty_detector.main.id
}

output "alerts_topic_arn" {
  description = "The security alerts SNS topic ARN."
  value       = aws_sns_topic.alerts.arn
}

output "config_bucket_name" {
  description = "The AWS Config delivery bucket name."
  value       = aws_s3_bucket.config.id
}

output "access_analyzer_arn" {
  description = "The IAM Access Analyzer ARN."
  value       = aws_accessanalyzer_analyzer.main.arn
}

output "cloudtrail_kms_key_arn" {
  description = "The CMK used to encrypt CloudTrail log files (Phase 5, CloudTrail.2)."
  value       = aws_kms_key.cloudtrail.arn
}

# Phase 5, posture remediation.
#
# These resources close the Security Hub (AWS Foundational Security Best
# Practices) findings that are free to fix and in scope for the lab. Each is
# mapped to its FSBP control ID. Findings that need a paid service, or a
# workload the lab deliberately does not run, are not fixed here; they are
# accepted with a reason in evidence/phase5/securityhub-baseline.md.
#
# Everything here is an account-, Region- or resource-level default. None of it
# launches compute or adds recurring cost beyond one KMS key (about 1 USD per
# month), which is within the budget.

# --- EC2.7: EBS encryption by default (Region) ------------------------------
resource "aws_ebs_encryption_by_default" "main" {
  enabled = true
}

# --- EC2.172: VPC Block Public Access, block internet gateway traffic -------
resource "aws_vpc_block_public_access_options" "main" {
  internet_gateway_block_mode = "block-bidirectional"
}

# --- EC2.182: block public access for EBS snapshots (account/Region) --------
resource "aws_ebs_snapshot_block_public_access" "main" {
  state = "block-all-sharing"
}

# --- S3.1: account-level S3 Block Public Access -----------------------------
# The three buckets already have bucket-level public-access blocks. This sets
# the same guarantee at the account level, so no future bucket can be made
# public either.
resource "aws_s3_account_public_access_block" "main" {
  account_id              = var.account_id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- IAM.7: strong account password policy ----------------------------------
# Applies to any IAM user with a console password. operator already uses MFA;
# this sets the length, complexity and rotation floor a bank's IAM standard
# expects.
resource "aws_iam_account_password_policy" "main" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}

# --- SSM.7: block public sharing of SSM documents (account/Region) ----------
resource "aws_ssm_service_setting" "doc_public_sharing" {
  setting_id    = "arn:aws:ssm:${var.region}:${var.account_id}:servicesetting/ssm/documents/console/public-sharing-permission"
  setting_value = "Disable"
}

# --- EC2.2: default security groups should allow no traffic -----------------
# A default security group cannot be deleted, so the hardening step is to strip
# every inbound and outbound rule from it. There are two: the lab VPC's and the
# account's default VPC's. Nothing in the lab uses either; the data path is the
# S3 gateway endpoint.
resource "aws_default_security_group" "lab" {
  vpc_id = aws_vpc.lab.id
  # No ingress or egress blocks: all rules removed.
}

data "aws_vpc" "default" {
  default = true
}

resource "aws_default_security_group" "default_vpc" {
  vpc_id = data.aws_vpc.default.id
}

# --- EC2.15: default subnets should not auto-assign public IPs ---------------
# Adopt the account's default subnets only to turn off automatic public IP
# assignment. Terraform never deletes a default subnet; it only manages this
# attribute. The lab launches no instances, so this is defence in depth.
resource "aws_default_subnet" "az_a" {
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false
}

resource "aws_default_subnet" "az_b" {
  availability_zone       = "${var.region}b"
  map_public_ip_on_launch = false
}

resource "aws_default_subnet" "az_c" {
  availability_zone       = "${var.region}c"
  map_public_ip_on_launch = false
}

# --- S3.13: lifecycle configuration on every bucket -------------------------
# Expire noncurrent object versions and clean up incomplete multipart uploads.
# All three buckets are versioned, so without this old versions accumulate
# forever.
resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    id     = "expire-noncurrent-and-abort-mpu"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "expire-noncurrent-and-abort-mpu"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 365
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "config" {
  bucket = aws_s3_bucket.config.id
  rule {
    id     = "expire-noncurrent-and-abort-mpu"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 365
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# --- CloudTrail.2: encrypt the trail at rest with a customer-managed key -----
# The log bucket is already SSE-S3. This adds a dedicated KMS key so CloudTrail
# envelope-encrypts each log file before delivery, which is what the control
# checks and what separates audit-log key control from the data key. A separate
# key (not the data CMK) keeps audit and data key policies independent.
data "aws_iam_policy_document" "cloudtrail_kms" {
  statement {
    sid    = "EnableRootAccountAdmin"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowCloudTrailEncrypt"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${var.account_id}:trail/*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.region}:${var.account_id}:trail/${var.trail_name}"]
    }
  }

  statement {
    sid    = "AllowCloudTrailDescribeKey"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:DescribeKey"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "cloudtrail" {
  description             = "CMK for CloudTrail log-file encryption (audit path)."
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.cloudtrail_kms.json
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/cloud-iam-lab-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

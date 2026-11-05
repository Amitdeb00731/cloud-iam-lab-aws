# Security Hub baseline and remediation triage (before)

**Standard:** AWS Foundational Security Best Practices (FSBP) v1.0.0
**Account:** 963910216975, Region eu-north-1
**Captured:** 2026-11-05, after Security Hub finished its first evaluation and
before any Phase 5 remediation.

## Baseline score

**Security score: 53 percent** (31 controls passed, 28 failed, 276 no data).

Failed checks by severity: 1 critical, 6 high, 31 medium, 4 low (42 individual
checks across the 28 failed controls).

The 276 "no data" controls are for services the lab does not run (RDS, EKS,
Redshift, SageMaker and so on). Security Hub does not count them in the score, so
the score is calculated over the 59 controls that have data. The score measures
improvement against best practice, not compliance or certification.

Evidence: `securityhub-score-before.png` (console overview) and
`raw/securityhub-fsbp-baseline.csv` (full control export).

## What already passes

The build's own controls are green at baseline: AWS Config (Config.1), CloudTrail
enabled and validated (CloudTrail.1, CloudTrail.4), GuardDuty and its protection
plans (GuardDuty.1/5/6/8/9/10), S3 public-access and TLS controls (S3.2, S3.3,
S3.5, S3.6, S3.8, S3.12), KMS key controls (KMS.2, KMS.3, KMS.5), no root access
key (IAM.4), MFA on the console user (IAM.5), key rotation (IAM.3) and Athena
logging (Athena.4). The posture work builds on a sound base.

## Remediation triage

Every failed control is triaged into fix (free and in scope) or accept (needs a
paid service or a workload the lab does not run, or is a documented design
choice).

### Fix (free, in scope)

| Control | Sev | Fix | Where |
| --- | --- | --- | --- |
| SSM.7 | Critical | Block public sharing of SSM documents | `remediation.tf` |
| EC2.2 | High | Strip all rules from both default security groups | `remediation.tf` |
| EC2.182 | High | Account block-public-access for EBS snapshots | `remediation.tf` |
| EC2.7 | Medium | EBS default encryption on | `remediation.tf` |
| EC2.15 | Medium | Default subnets stop auto-assigning public IPs | `remediation.tf` |
| EC2.172 | Medium | VPC Block Public Access, block IGW traffic | `remediation.tf` |
| S3.1 | Medium | Account-level S3 Block Public Access | `remediation.tf` |
| IAM.7 | Medium | Strong account password policy | `remediation.tf` |
| CloudTrail.2 | Medium | Dedicated KMS key encrypts the trail at rest | `remediation.tf` + `cloudtrail.tf` |
| Account.1 | Medium | Set the account security contact | CLI (keeps the contact details out of the repo and state) |
| S3.13 | Low | Lifecycle rules on all three buckets | `remediation.tf` |

**Root MFA.** The credential report (`credential-report.md`) shows the workload
account root has no MFA device. This is the real identity gap and is closed in
Step 4 by enabling root MFA from the root sign-in. Note the matching FSBP control
IAM.6 asks specifically for a hardware MFA device and currently reports "no data";
a virtual (authenticator app) MFA closes the security gap but will not by itself
flip IAM.6 to passed, which is called out honestly rather than claimed.

### Accept (paid, not applicable, or by design)

| Control | Sev | Reason |
| --- | --- | --- |
| GuardDuty.7, GuardDuty.11, GuardDuty.12, GuardDuty.13 | High/Medium | Runtime Monitoring needs agents on EC2, ECS or EKS. The lab runs no compute. Paid and not applicable. |
| Inspector.3 | High | Inspector Lambda code scanning is paid and there are no Lambda functions. |
| Macie.1 | Medium | Macie is paid; the handful of synthetic objects does not warrant sensitive-data discovery. |
| EC2.10, EC2.55, EC2.56, EC2.57, EC2.58, EC2.60 | Medium | Interface VPC endpoints for EC2, ECR, Docker Registry and Systems Manager. Each is a paid endpoint for a service the lab does not use. |
| S3.9 | Medium | Server access logging. CloudTrail S3 data events already record object access, and logging the log and config buckets would log the logs. |
| CloudTrail.5 | Medium | CloudTrail to CloudWatch Logs. Athena over S3 plus GuardDuty to EventBridge to SNS already give query and alerting; ingesting every event into CloudWatch Logs is avoided to stay within budget. |
| SSM.6 | Medium | Systems Manager Automation logging. No automation documents are in use. |
| IAM.2 | Low | operator has one directly-attached policy by design: a single base identity whose only permission is an MFA-gated AssumeRole to the lab roles. A group for one user adds nothing. See `access-review.md`. |
| EC2.6 | Medium | VPC flow logs. The lab runs no instances or traffic-bearing interfaces, so flow logs would capture almost nothing. Network path control is the no-internet-gateway VPC and the S3 gateway endpoint. Candidate future work. |

## Projected result

Fixing the eleven controls above moves 28 failed to 17 and 31 passed to 42, a
projected score of about 71 percent. The exact after figure is captured in
`securityhub-score-after.png` once Security Hub re-evaluates (allow an hour or
two after applying).

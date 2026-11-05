# IAM control write-up

| Field | Value |
| --- | --- |
| Document | Access-management control mapping |
| Account | 963910216975 (workload), under AWS Organizations management account 618790904616 |
| Region | eu-north-1 |
| Date | 2026-11-05 |
| Author | Amit Kiran Deb |
| Audience | Technology-risk and controls reader |

## 1. Purpose

This document maps the identity and access controls built in the lab to the
access-management expectations a bank's controls function checks. It is written for
a risk reader rather than an engineer: each control domain states the expectation,
what the account implements, the evidence, and the gap a production landing zone
would close. The lab shows the control design; it does not claim certification.

## 2. Control environment summary

The account runs on a single daily identity with no standing privilege and three
roles it can assume only with multi-factor authentication. Administrative access is
never standing; it is assumed for a capped, logged window and dropped. Guardrails
are set in the management account as service control policies and bind the
`Workloads` organisational unit. Every action is recorded in CloudTrail, queried in
Athena, and supplemented by GuardDuty. The posture was measured with Security Hub
against the AWS Foundational Security Best Practices standard, and a documented
access review was run with the IAM credential report and IAM Access Analyzer.

## 3. Mapping to access-management control domains

### 3.1 Joiner, mover, leaver (provisioning)

**Expectation.** Access is granted through a controlled process, changes are
deliberate, and access is removed when no longer needed.

**Implemented.** Identities and their permissions are defined as code in
`config/iam/` and Terraform, so every grant is explicit and reviewable. The
`operator` identity has one inline policy whose only permission is to assume the
lab roles; the roles carry the permissions. Removal is the reverse of the
documented creation.

**Production note.** The lab provisions with IAM roles because the account's IAM
Identity Center instance could not expose multi-account permission sets. A
production landing zone would front these roles with Identity Center or an external
identity provider, so joiner, mover, and leaver events are driven from a central
directory and the local base credential is no longer required.

### 3.2 Privileged access management

**Expectation.** Administrative access is limited, time-bound, logged, and never
standing.

**Implemented.** `AdminJITRole` grants `AdministratorAccess` only when assumed, with
a maximum session duration of one hour, and only when the sign-in carried MFA. No
identity holds standing administrator. The account root is credential-less: it has
no password, access keys, or MFA device, and any root action is brokered from the
management account through centralized root access, whose own root is protected by
MFA. This is stronger than placing a password and MFA on the member root. Evidence:
[`evidence/phase5/access-review.md`](../evidence/phase5/access-review.md), and the
privilege-escalation detection in
[`evidence/phase4/03-admin-outside-jit.md`](../evidence/phase4/03-admin-outside-jit.md).

### 3.3 Least privilege and segregation of duties

**Expectation.** Each identity holds only the access it needs, and sensitive data
is separated from general access.

**Implemented.** The three roles are scoped by managed policy
(`ReadOnlyAccess`, `PowerUserAccess`, `AdministratorAccess`) and used for distinct
purposes. Data is separated by classification prefix on the storage bucket:
`public/`, `internal/`, and `confidential/`, with the confidential prefix readable
only by `AdminJITRole` through a bucket-policy statement scoped to that prefix.
Service control policies on the `Workloads` organisational unit add
organisation-wide denies: one Region only (`deny-outside-eu-north-1`), no disabling
the audit path (`deny-disable-security`), and MFA required on sensitive actions
(`require-mfa-sensitive`). Evidence: `config/scp/` and
[`evidence/phase2/README.md`](../evidence/phase2/README.md).

### 3.4 Authentication and credentials

**Expectation.** Strong authentication is enforced, and long-lived credentials are
minimised and justified.

**Implemented.** Every role assumption requires MFA through the role trust policy
(`aws:MultiFactorAuthPresent`), and every successful sign-in in the detection
exercise used MFA. The account holds one long-lived access key, the `operator` CLI
base credential, which on its own can do nothing but start an MFA-gated role
assumption. It is recognised, in active use, and acknowledged in the access review
rather than hidden. A strong account password policy was applied during the posture
work. Evidence:
[`evidence/phase4/02-valid-account-unusual-source.md`](../evidence/phase4/02-valid-account-unusual-source.md)
and [`evidence/phase5/access-review.md`](../evidence/phase5/access-review.md).

### 3.5 Monitoring and detection

**Expectation.** Privileged and sensitive activity is logged and monitored, and
alerts reach a responder.

**Implemented.** A multi-region CloudTrail trail with log-file validation records
management events and scoped S3 data events to a hardened log bucket, queried in
Athena. GuardDuty adds managed threat detection, routed through EventBridge and SNS
to an inbox, with end-to-end delivery proven. Five detections, one per technique,
exist as Athena queries and portable Sigma rules, scored in a coverage matrix.
Evidence: [`evidence/phase3/telemetry-coverage.md`](../evidence/phase3/telemetry-coverage.md)
and [`evidence/phase4/coverage-matrix.md`](../evidence/phase4/coverage-matrix.md).

### 3.6 Access review and recertification

**Expectation.** Access is reviewed periodically, with a recorded decision for each
identity and path.

**Implemented.** A documented review used the IAM credential report and IAM Access
Analyzer to list every identity and every external path into the account, and
recorded a decision for each: `operator` and the three roles kept, root kept
credential-less, and the two Access Analyzer findings (the management account
assuming an AWS-managed role) reviewed and marked intended. No standing admin, no
public sharing, and no stale or unexpected credential were found. Evidence:
[`evidence/phase5/access-review.md`](../evidence/phase5/access-review.md).

## 4. Control summary

| Control domain | Mechanism | Status | Evidence |
| --- | --- | --- | --- |
| Provisioning | IAM roles and inline policy as code | Implemented, IdP fronting is the production step | `config/iam/` |
| Privileged access | Just-in-time `AdminJITRole`, one-hour cap, MFA, credential-less root | Implemented | `evidence/phase5/access-review.md` |
| Least privilege and SoD | Scoped roles, prefix-level data separation, three SCPs | Implemented | `config/scp/`, `evidence/phase2` |
| Authentication | MFA on every assumption, one justified base key | Implemented | `evidence/phase5/access-review.md` |
| Monitoring | CloudTrail, Athena, GuardDuty, five scored detections | Implemented | `evidence/phase3`, `evidence/phase4` |
| Access review | Credential report plus Access Analyzer, decision per identity | Implemented | `evidence/phase5/access-review.md` |

## 5. Known limitations

Stated plainly, so the mapping is not overclaimed:

- **Role-based, not Identity Center.** The account could not expose multi-account
  permission sets, so access uses IAM roles with a base credential. A production
  landing zone would centralise this behind Identity Center or an external IdP.
- **Posture measures improvement, not compliance.** The Security Hub score moved
  from a 53 percent baseline towards a projected 71 percent after remediation; it
  is a best-practice measure, not a certification. The exact after figure follows
  the service's periodic re-evaluation. Evidence:
  [`evidence/phase5/securityhub-baseline.md`](../evidence/phase5/securityhub-baseline.md).
- **One detection is partial.** Unusual-source credential use (T1078.004) relies on
  the GuardDuty managed layer, because a genuine new-source sign-in could not be
  produced in a single-location lab. This is scored honestly in the coverage matrix.

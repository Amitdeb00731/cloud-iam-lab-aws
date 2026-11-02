# Phase 3 telemetry coverage

This note records what visibility the lab now has and the evidence that each
source reaches an analyst. Phase 3 adds three sources on top of the Phase 2
data-protection controls: an organisation-wide audit trail, queryable storage
over that trail, and managed threat detection with alerting.

All resources are in eu-north-1 in account 963910216975. Captured values below
are taken from the live account; object keys and identifiers are from the lab
itself, and no credentials, email addresses or personal data are reproduced.

## Coverage summary

| Source | Service | Scope | Routed to | Arrival proven |
| --- | --- | --- | --- | --- |
| API and control-plane activity | CloudTrail (management events) | All Regions, all read and write management events | S3 log bucket, Athena | Yes |
| Object-level data access | CloudTrail (S3 data events) | GetObject, PutObject and DeleteObject on the data bucket only | S3 log bucket, Athena | Yes |
| Managed threat detection | GuardDuty | Account-wide, eu-north-1 detector | EventBridge to SNS to email | Yes |

Design notes:

- The S3 data-event selector is scoped to the single data bucket, not to all
  buckets, so the trail captures object access on the asset that matters while
  keeping CloudTrail data-event charges contained.
- The log bucket is itself hardened: Block Public Access on all four settings,
  bucket-owner-enforced object ownership, versioning, SSE-S3 default encryption,
  a TLS-only bucket policy, and a CloudTrail service policy pinned to the trail
  ARN with `aws:SourceArn`.
- AWS Config is deliberately deferred to Phase 5. It bills per configuration
  item and per rule evaluation, so it is introduced alongside the posture work
  rather than left running through the detection phase.

## Source 1: management events

A broad read of recent activity returned management events from the expected
principals (the operator session and the assumed AdminJITRole session),
confirming the trail is delivering and the Athena table parses the records.

Representative event names observed: `GetBucketAcl`, `GetBucketLocation`,
and the Athena and Glue calls raised by querying the table itself. Trail status
at first delivery:

```
aws cloudtrail get-trail-status --name cloud-iam-lab-trail
"IsLogging": true
"TimeLoggingStarted": "2026-11-01T19:00:02Z"
```

Raw query output is preserved under `evidence/phase3/raw/`.

## Source 2: S3 data events

Object-level access on the data bucket is captured. A GetObject against a
confidential-tier sample object appears in the trail with the reading
principal and the object key:

```
eventname:        GetObject
eventsource:      s3.amazonaws.com
bucket:           cloud-iam-lab-data-963910216975
key:              internal/runbook.txt
principal (role): AdminJITRole
```

Note on timing: S3 data events can lag management events by several minutes
before they are queryable in Athena. A query run immediately after the read
returned nothing; the same query a short while later returned the event. This
latency is expected and is worth stating in the write-up so a reader does not
mistake it for a gap in coverage.

## Source 3: GuardDuty alerting

GuardDuty is enabled with an account-level detector in eu-north-1. Findings are
routed through EventBridge (rule matching source `aws.guardduty`, detail-type
`GuardDuty Finding`) to the `cloud-iam-lab-security-alerts` SNS topic, which has
an email subscription.

End-to-end delivery was proven with a sample finding. After the email
subscription was confirmed, a fresh sample finding was generated and the alert
arrived in the inbox through SNS. Sanitised finding envelope:

```
detail-type: GuardDuty Finding
source:      aws.guardduty
type:        UnauthorizedAccess:IAMUser/TorIPCaller
severity:    5.0
note:        [SAMPLE] generated with create-sample-findings for the delivery test
```

Operational note for the write-up: SNS does not resend notifications for a
finding that fired before the subscription was confirmed. During testing the
first sample was generated before the subscription was confirmed, so no email
arrived; generating a fresh finding of a different type after confirming the
subscription produced the alert. The lesson for an on-call runbook is to
confirm the subscription first, then test.

## What this gives the detection phase

With all three sources proven, Phase 4 can write detections as Athena queries
over `cloud_iam_lab.cloudtrail_logs` and pair them with GuardDuty's managed
findings, mapping each to MITRE ATT&CK and validating against benign activity
in the lab's own test accounts.
